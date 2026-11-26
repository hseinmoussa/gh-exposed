// Package report renders scan results as text, Markdown or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/hseinmoussa/gh-exposed/internal/incident"
	"github.com/hseinmoussa/gh-exposed/internal/scan"
)

// Format is an output format.
type Format string

const (
	Text     Format = "text"
	Markdown Format = "markdown"
	JSON     Format = "json"
)

// ParseFormat validates a --format value.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(s)) {
	case Text, "":
		return Text, nil
	case Markdown, "md":
		return Markdown, nil
	case JSON:
		return JSON, nil
	}
	return "", fmt.Errorf("unknown --format %q (use text, markdown or json)", s)
}

// Scan writes a scan report.
func Scan(w io.Writer, f Format, r *scan.Report) error {
	switch f {
	case JSON:
		return writeJSON(w, r)
	case Markdown:
		return scanDoc(w, r, true)
	default:
		return scanDoc(w, r, false)
	}
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// doc writes either plain text or Markdown from one template, so the two
// formats can never disagree on content.
type doc struct {
	w  *errWriter
	md bool
}

// errWriter keeps the first write error so a renderer can write freely and
// check once at the end (the pattern from "Errors are values").
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(b []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(b)
	e.err = err
	return n, err
}

func newDoc(w io.Writer, md bool) doc { return doc{w: &errWriter{w: w}, md: md} }

func (d doc) h(level int, s string) {
	if d.md {
		fmt.Fprintf(d.w, "%s %s\n\n", strings.Repeat("#", level), s)
		return
	}
	// Levels 1-2 are upper-cased section titles; level 3 names a repository,
	// whose case must be kept.
	if level <= 2 {
		fmt.Fprintf(d.w, "%s\n%s\n\n", strings.ToUpper(s), strings.Repeat("=", len(s)))
		return
	}
	fmt.Fprintf(d.w, "%s\n%s\n\n", s, strings.Repeat("-", len(s)))
}

func (d doc) p(format string, a ...any) { fmt.Fprintf(d.w, format+"\n\n", a...) }

func (d doc) item(format string, a ...any) { fmt.Fprintf(d.w, "- "+format+"\n", a...) }

func (d doc) code(s string) string {
	if d.md {
		return "`" + s + "`"
	}
	return s
}

func (d doc) table(head []string, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	if d.md {
		esc := func(s string) string { return strings.ReplaceAll(s, "|", `\|`) }
		fmt.Fprintf(d.w, "| %s |\n|%s\n", strings.Join(head, " | "), strings.Repeat("---|", len(head)))
		for _, r := range rows {
			for i := range r {
				r[i] = esc(r[i])
			}
			fmt.Fprintf(d.w, "| %s |\n", strings.Join(r, " | "))
		}
		fmt.Fprintln(d.w)
		return
	}
	width := make([]int, len(head))
	for i, h := range head {
		width[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if len(c) > width[i] {
				width[i] = len(c)
			}
		}
	}
	line := func(cells []string) {
		parts := make([]string, len(cells))
		for i, c := range cells {
			parts[i] = c + strings.Repeat(" ", width[i]-len(c))
		}
		fmt.Fprintln(d.w, strings.TrimRight(strings.Join(parts, "  "), " "))
	}
	line(head)
	seps := make([]string, len(head))
	for i := range head {
		seps[i] = strings.Repeat("-", width[i])
	}
	line(seps)
	for _, r := range rows {
		line(r)
	}
	fmt.Fprintln(d.w)
}

func verdictLabel(v incident.Verdict) string {
	switch v {
	case incident.Confirmed:
		return "CONFIRMED"
	case incident.Possible:
		return "POSSIBLE"
	}
	return "not exposed"
}

func scanDoc(w io.Writer, r *scan.Report, md bool) error {
	d := newDoc(w, md)
	in := r.Incident
	d.h(1, "gh-exposed: "+in.Title)
	if in.URL != "" {
		d.p("Advisory: %s", in.URL)
	}
	d.p("Exposure window: %s to %s (UTC).%s", in.Start.Format(time.RFC3339), in.End.Format(time.RFC3339), suffix(in.WindowNote))
	if in.Payload != "" {
		d.p("What the malicious code did: %s", in.Payload)
	}

	s := r.Summary
	d.h(2, "Result")
	switch r.Worst() {
	case incident.Confirmed:
		d.p("%d run(s) CONFIRMED to have executed the compromised code, %d more POSSIBLY did. Rotate the secrets below, starting with critical.", s.Confirmed, s.Possible)
	case incident.Possible:
		if s.Possible > 0 {
			d.p("No run is confirmed, but %d run(s) POSSIBLY executed the compromised code and nothing could clear them. Treat their secrets as exposed.", s.Possible)
		}
	case incident.NotAffected:
		if r.Incomplete() {
			break
		}
		if s.HistoryGaps > 0 {
			d.p("No run in the window executed the compromised code, but %d repositories have no run history that reaches the window, so this is not a complete answer for them (see their notes).", s.HistoryGaps)
		} else {
			d.p("No run in the scanned repositories executed the compromised code.")
		}
	}
	if r.Incomplete() {
		d.p("THIS RESULT IS INCOMPLETE: %d repositories could not be scanned and %d runs could not be assessed (their workflow file could not be read and their logs did not settle it). Re-run the scan; their details are below.", s.RepoErrs, s.Unassessed)
	}
	if s.PossibleFiles > 0 {
		d.p("%d workflow file(s) in repositories whose run history GitHub no longer keeps used the action with a movable ref during the window. Any run of them in the window executed the compromised code; their secrets are in the rotation list.", s.PossibleFiles)
	}
	d.table([]string{"Repositories", "Runs in window", "Confirmed", "Possible", "Used the action, not exposed", "Repos without run history", "Repos with errors"},
		[][]string{{fmt.Sprint(s.Repos), fmt.Sprint(s.Runs), fmt.Sprint(s.Confirmed), fmt.Sprint(s.Possible), fmt.Sprint(s.Cleared), fmt.Sprint(s.HistoryGaps), fmt.Sprint(s.RepoErrs)}})

	if len(r.Rotation) > 0 {
		d.h(2, "Secrets to rotate")
		d.p("GITHUB_TOKEN is not listed: GitHub revokes it when the job ends. Secret values are never shown; only names.")
		var rows [][]string
		for _, x := range r.Rotation {
			rows = append(rows, []string{strings.ToUpper(x.Priority), x.Repo, d.code(x.Secret), x.Why, runList(x.Runs)})
		}
		d.table([]string{"Priority", "Repository", "Secret", "Why", "Runs"}, rows)
	}

	var flagged []scan.RepoResult
	for _, repo := range r.Repos {
		if len(repo.Runs) > 0 || repo.Error != "" || len(repo.Notes) > 0 {
			flagged = append(flagged, repo)
		}
	}
	if len(flagged) > 0 {
		d.h(2, "Runs")
	}
	for _, repo := range flagged {
		d.h(3, fmt.Sprintf("%s (%s)", repo.Repo, repo.Visibility))
		if repo.Error != "" {
			d.p("Could not scan: %s", repo.Error)
		}
		for _, n := range repo.Notes {
			d.item("%s", n)
		}
		if len(repo.Notes) > 0 {
			fmt.Fprintln(d.w)
		}
		runs := append([]scan.RunResult{}, repo.Runs...)
		sort.SliceStable(runs, func(i, j int) bool { return runs[i].Verdict > runs[j].Verdict })
		for _, run := range runs {
			header := fmt.Sprintf("%s  run %d  %s  %s on %s  started %s",
				verdictLabel(run.Verdict), run.ID, run.Workflow, orDash(run.Event), orDash(run.Branch),
				run.StartedAt.UTC().Format(time.RFC3339))
			if run.Kind == scan.KindWorkflowFile {
				header = fmt.Sprintf("%s  workflow %s  on %s at %s  (no run history)",
					verdictLabel(run.Verdict), run.Workflow, orDash(run.Branch), short(run.SHA))
			}
			if d.md {
				header = "**" + header + "**"
			}
			fmt.Fprintln(d.w, header)
			if run.URL != "" {
				fmt.Fprintln(d.w, run.URL)
			}
			if d.md {
				fmt.Fprintln(d.w) // Markdown needs a blank line before a list
			}
			for _, e := range run.Evidence {
				d.item("evidence: %s", e)
			}
			if run.Unassessed {
				d.item("NOT ASSESSED: the workflow file could not be read, and the logs did not settle it")
			}
			for _, x := range run.Reasons {
				d.item("%s", x)
			}
			for _, j := range run.Jobs {
				d.item("job %s: %s (%s) via %s", d.code(j.Job), d.code(j.Action), j.Reason, chain(j.Chain))
			}
			if len(run.LeakedSecrets) > 0 {
				d.item("secret names found in the log: %s", strings.Join(run.LeakedSecrets, ", "))
			}
			if run.Verdict != incident.NotAffected {
				switch {
				case run.AllSecrets:
					d.item("secrets readable: ALL (the job uses secrets: inherit, toJSON(secrets) or a dynamic secrets[...] lookup)")
				case len(run.Secrets) > 0:
					d.item("secrets readable: %s", strings.Join(run.Secrets, ", "))
				}
			}
			d.item("logs: %s", run.LogStatus)
			fmt.Fprintln(d.w)
		}
	}
	if len(r.Notes) > 0 {
		d.h(2, "Limits of this scan")
		for _, n := range r.Notes {
			d.item("%s", n)
		}
		fmt.Fprintln(d.w)
	}
	d.p("Generated by gh-exposed at %s.", r.Generated.Format(time.RFC3339))
	return d.w.err
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func suffix(s string) string {
	if s == "" {
		return ""
	}
	return " " + s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func runList(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for i, id := range ids {
		if i == 5 {
			parts = append(parts, fmt.Sprintf("+%d more", len(ids)-5))
			break
		}
		parts = append(parts, fmt.Sprint(id))
	}
	return strings.Join(parts, ", ")
}

func chain(c []scan.Link) string {
	parts := make([]string, len(c))
	for i, l := range c {
		parts[i] = fmt.Sprintf("%s:%d", l.File, l.Line)
	}
	return strings.Join(parts, " -> ")
}

// Usage writes a usage report.
func Usage(w io.Writer, f Format, r *scan.UsageReport) error {
	if f == JSON {
		return writeJSON(w, r)
	}
	d := newDoc(w, f == Markdown)
	d.h(1, "Where "+r.Action+" is used")
	d.p("%d repositories scanned on their default branch; %d uses found.", r.Repos, len(r.Rows))
	var rows [][]string
	mutable := 0
	for _, x := range r.Rows {
		how := "direct"
		if !x.Direct {
			how = "via " + chain(x.Chain[:len(x.Chain)-1])
		}
		if x.Pin == "mutable" {
			mutable++
		}
		rows = append(rows, []string{x.Repo, x.Workflow, x.Job, d.code(x.Uses), string(x.Pin), how})
	}
	d.table([]string{"Repository", "Workflow", "Job", "Uses", "Pin", "How"}, rows)
	if mutable > 0 {
		d.p("%d use(s) are pinned to a tag or branch, which the action's owner (or an attacker with their credentials) can move. Pin to a full commit SHA.", mutable)
	}
	for _, e := range r.Errors {
		d.item("error: %s", e)
	}
	for _, n := range r.Notes {
		d.item("note: %s", n)
	}
	return d.w.err
}

// Incidents writes the built-in catalogue.
func Incidents(w io.Writer, f Format, list []incident.Incident) error {
	if f == JSON {
		return writeJSON(w, list)
	}
	d := newDoc(w, f == Markdown)
	var rows [][]string
	for _, in := range list {
		var actions []string
		for _, t := range in.Targets {
			actions = append(actions, t.Action)
		}
		rows = append(rows, []string{d.code(in.ID), in.Start.Format("2006-01-02"), strings.Join(actions, ", "), in.Advisory})
	}
	d.table([]string{"ID", "Date", "Actions", "Advisory"}, rows)
	return d.w.err
}
