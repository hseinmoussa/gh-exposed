package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hseinmoussa/gh-exposed/internal/ghapi"
	"github.com/hseinmoussa/gh-exposed/internal/incident"
	"github.com/hseinmoussa/gh-exposed/internal/logscan"
	"github.com/hseinmoussa/gh-exposed/internal/workflow"
)

// Options control a scan.
type Options struct {
	Incident incident.Incident
	Repos    []string // owner/repo
	Owners   []string // organizations or users: every repository is scanned
	// Logs downloads and scans run logs for runs the workflow files flag.
	Logs bool
	// Deep scans the logs of EVERY run in the window, not only flagged ones.
	// It finds compromised actions reached through paths the workflow files
	// no longer show, at the cost of one log download per run.
	Deep        bool
	MaxLogBytes int64
	Concurrency int
	// Progress, if set, receives one line per repository as it finishes.
	Progress func(string)
}

// JobHit is one job that reached a compromised action.
type JobHit struct {
	Job     string           `json:"job"`
	Action  string           `json:"action"`
	Verdict incident.Verdict `json:"verdict"`
	Reason  string           `json:"reason"`
	Chain   []Link           `json:"chain"`
}

// RunResult is one run that reached a compromised action.
type RunResult struct {
	ID        int64            `json:"id"`
	Attempts  int              `json:"attempts"`
	URL       string           `json:"url"`
	Workflow  string           `json:"workflow"`
	Event     string           `json:"event"`
	Branch    string           `json:"branch"`
	SHA       string           `json:"head_sha"`
	StartedAt time.Time        `json:"started_at"`
	Verdict   incident.Verdict `json:"verdict"`
	Reasons   []string         `json:"reasons"`
	Jobs      []JobHit         `json:"jobs,omitempty"`
	// Secrets the affected jobs could read (names only).
	Secrets []string `json:"secrets"`
	// AllSecrets: a job read every secret (inherit / toJSON / dynamic).
	AllSecrets bool `json:"all_secrets"`
	// LeakedSecrets: names found printed (encoded) in this run's log.
	LeakedSecrets []string `json:"leaked_secrets,omitempty"`
	FromFork      bool     `json:"from_fork"`
	LogStatus     string   `json:"log_status"`
	Evidence      []string `json:"evidence,omitempty"`
}

// RepoResult is one scanned repository.
type RepoResult struct {
	Repo         string      `json:"repo"`
	Visibility   string      `json:"visibility"`
	RunsInWindow int         `json:"runs_in_window"`
	Runs         []RunResult `json:"runs,omitempty"`
	// RepoSecrets is filled when a job read all secrets and the token could
	// list them.
	RepoSecrets []string `json:"repo_secrets,omitempty"`
	Notes       []string `json:"notes,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// Rotation is one secret to rotate.
type Rotation struct {
	Repo     string  `json:"repo"`
	Secret   string  `json:"secret"`
	Priority string  `json:"priority"` // critical, high, medium
	Why      string  `json:"why"`
	Runs     []int64 `json:"runs"`
}

// Summary counts.
type Summary struct {
	Repos     int `json:"repos_scanned"`
	RepoErrs  int `json:"repos_with_errors"`
	Runs      int `json:"runs_in_window"`
	Confirmed int `json:"runs_confirmed"`
	Possible  int `json:"runs_possible"`
	Cleared   int `json:"runs_used_action_not_exposed"`
}

// Report is the whole result.
type Report struct {
	Tool      string            `json:"tool"`
	Generated time.Time         `json:"generated_at"`
	Incident  incident.Incident `json:"incident"`
	Summary   Summary           `json:"summary"`
	Repos     []RepoResult      `json:"repos"`
	Rotation  []Rotation        `json:"rotation"`
	Notes     []string          `json:"notes,omitempty"`
}

// Worst returns the most severe verdict in the report.
func (r *Report) Worst() incident.Verdict {
	switch {
	case r.Summary.Confirmed > 0:
		return incident.Confirmed
	case r.Summary.Possible > 0:
		return incident.Possible
	}
	return incident.NotAffected
}

// Run performs the scan.
func Run(ctx context.Context, src Source, o Options) (*Report, error) {
	if err := o.Incident.Validate(); err != nil {
		return nil, err
	}
	if o.Concurrency < 1 {
		o.Concurrency = 4
	}
	if o.MaxLogBytes <= 0 {
		o.MaxLogBytes = 500 << 20
	}
	repos, err := listTargets(ctx, src, o)
	if err != nil {
		return nil, err
	}
	res := newResolver(src)
	rep := &Report{Tool: "gh-exposed", Generated: time.Now().UTC(), Incident: o.Incident}
	results := make([]RepoResult, len(repos))
	sem := make(chan struct{}, o.Concurrency)
	var wg sync.WaitGroup
	for i, repo := range repos {
		wg.Add(1)
		go func(i int, repo ghapi.Repo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = scanRepo(ctx, src, res, o, repo)
			if o.Progress != nil {
				r := results[i]
				o.Progress(fmt.Sprintf("%s: %d runs in window, %d flagged", r.Repo, r.RunsInWindow, len(r.Runs)))
			}
		}(i, repo)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rep.Repos = results
	for _, r := range results {
		rep.Summary.Repos++
		rep.Summary.Runs += r.RunsInWindow
		if r.Error != "" {
			rep.Summary.RepoErrs++
		}
		for _, run := range r.Runs {
			switch run.Verdict {
			case incident.Confirmed:
				rep.Summary.Confirmed++
			case incident.Possible:
				rep.Summary.Possible++
			default:
				rep.Summary.Cleared++
			}
		}
	}
	rep.Rotation = rotation(results)
	rep.Notes = res.Notes()
	sort.Strings(rep.Notes)
	return rep, nil
}

func listTargets(ctx context.Context, src Source, o Options) ([]ghapi.Repo, error) {
	seen := map[string]bool{}
	var out []ghapi.Repo
	add := func(r ghapi.Repo) {
		k := strings.ToLower(r.FullName)
		if !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	for _, owner := range o.Owners {
		rs, err := src.ListRepos(ctx, owner)
		if err != nil {
			return nil, fmt.Errorf("list repositories of %s: %w", owner, err)
		}
		for _, r := range rs {
			add(r)
		}
	}
	for _, name := range o.Repos {
		r, err := src.GetRepo(ctx, name)
		if err != nil {
			// Keep going: report the repository with its error rather than
			// abandoning the whole scan.
			r = ghapi.Repo{FullName: name, Visibility: "unknown"}
		}
		add(r)
	}
	if len(out) == 0 {
		return nil, errors.New("no repositories to scan: pass --repo or --owner")
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].FullName) < strings.ToLower(out[j].FullName) })
	return out, nil
}

func visibility(r ghapi.Repo) string {
	switch {
	case r.Visibility != "":
		return r.Visibility
	case r.Private:
		return "private"
	default:
		return "public"
	}
}

func scanRepo(ctx context.Context, src Source, res *resolver, o Options, repo ghapi.Repo) RepoResult {
	in := o.Incident
	out := RepoResult{Repo: repo.FullName, Visibility: visibility(repo)}
	start, end := in.Start, in.End
	for _, t := range in.Targets {
		s, e := in.Window(t)
		if s.Before(start) {
			start = s
		}
		if e.After(end) {
			end = e
		}
	}
	runs, err := src.ListRuns(ctx, repo.FullName, start, end)
	if err != nil {
		out.Error = "list runs: " + err.Error()
		return out
	}
	out.RunsInWindow = len(runs)

	// Runs are independent and dominated by log downloads, so they are
	// scanned in parallel. Results keep the listing order (newest first).
	type slot struct {
		rr   RunResult
		keep bool
	}
	slots := make([]slot, len(runs))
	sem := make(chan struct{}, o.Concurrency)
	var wg sync.WaitGroup
	for i, run := range runs {
		if run.Conclusion == "skipped" || run.Conclusion == "startup_failure" {
			continue // the run never executed a step
		}
		wg.Add(1)
		go func(i int, run ghapi.Run) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			rr, keep := scanRun(ctx, src, res, o, repo.FullName, run)
			slots[i] = slot{rr, keep}
		}(i, run)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		out.Error = err.Error()
		return out
	}
	needRepoSecrets := false
	for _, s := range slots {
		if !s.keep {
			continue
		}
		out.Runs = append(out.Runs, s.rr)
		if s.rr.AllSecrets && s.rr.Verdict != incident.NotAffected {
			needRepoSecrets = true
		}
	}
	if needRepoSecrets {
		names, err := src.SecretNames(ctx, repo.FullName)
		switch {
		case err != nil:
			out.Notes = append(out.Notes, "a flagged job read ALL secrets, but the token could not list this repository's secret names ("+shortErr(err)+"); rotate every secret it can use")
		default:
			sort.Strings(names)
			out.RepoSecrets = names
		}
	}
	return out
}

func shortErr(err error) string {
	switch {
	case errors.Is(err, ghapi.ErrForbidden):
		return "permission denied"
	case errors.Is(err, ghapi.ErrNotFound):
		return "not found"
	}
	return err.Error()
}

func runStart(r ghapi.Run) time.Time {
	if !r.RunStartedAt.IsZero() {
		return r.RunStartedAt
	}
	return r.CreatedAt
}

// scanRun assesses one run. keep is false for a run that never reached a
// compromised action (it is counted, not listed).
func scanRun(ctx context.Context, src Source, res *resolver, o Options, repo string, run ghapi.Run) (RunResult, bool) {
	in := o.Incident
	started := runStart(run)
	rr := RunResult{
		ID: run.ID, Attempts: max(run.RunAttempt, 1), URL: run.HTMLURL, Workflow: run.Path,
		Event: run.Event, Branch: run.HeadBranch, SHA: run.HeadSHA, StartedAt: started,
		FromFork: run.FromFork(repo), LogStatus: "not downloaded",
	}

	// 1. Static assessment from the workflow file at the commit that ran.
	secrets := map[string]bool{}
	if strings.HasPrefix(run.Path, ".github/workflows/") {
		data, err := res.get(ctx, repo, run.Path, run.HeadSHA)
		var wf *workflow.File
		if err == nil {
			wf, err = workflow.ParseWorkflow(data)
		}
		if err != nil {
			rr.Reasons = append(rr.Reasons, "workflow file could not be read at "+short(run.HeadSHA)+": "+shortErr(err))
		}
		if wf != nil {
			for _, job := range wf.Jobs {
				found := res.expand(ctx, repo, run.HeadSHA, job.Uses, run.Path+"@"+short(run.HeadSHA), nil, 0, map[string]bool{})
				jobHit := false
				for _, f := range found {
					for _, t := range in.Targets {
						s, e := in.Window(t)
						if started.Before(s) || started.After(e) {
							continue
						}
						v, why := t.Assess(f.Ref)
						if why == "" {
							continue
						}
						rr.Jobs = append(rr.Jobs, JobHit{Job: job.ID, Action: f.Ref.Raw, Verdict: v, Reason: why, Chain: f.Chain})
						if v > rr.Verdict {
							rr.Verdict = v
						}
						if v != incident.NotAffected {
							jobHit = true
						}
					}
				}
				if jobHit {
					for _, s := range job.Secrets {
						secrets[s] = true
					}
					if job.AllSecrets {
						rr.AllSecrets = true
					}
				}
			}
		}
	} else if run.Path != "" {
		rr.Reasons = append(rr.Reasons, "run of "+run.Path+" has no workflow file in the repository (a GitHub-managed workflow); only its logs can show what ran")
	}
	staticHit := len(rr.Jobs) > 0

	// 2. Log evidence.
	wantLogs := o.Logs && (rr.Verdict == incident.Possible || o.Deep)
	if wantLogs {
		ev, status := fetchEvidence(ctx, src, o, repo, run)
		rr.LogStatus = status
		if ev != nil {
			applyEvidence(&rr, in, ev)
		}
	}
	if !staticHit && rr.Verdict == incident.NotAffected && len(rr.Evidence) == 0 {
		return rr, false
	}

	if rr.Verdict == incident.Possible {
		rr.Reasons = append([]string{possibleSummary(rr)}, rr.Reasons...)
	}
	for s := range secrets {
		rr.Secrets = append(rr.Secrets, s)
	}
	sort.Strings(rr.Secrets)
	if rr.FromFork {
		rr.Reasons = append(rr.Reasons, "triggered by a pull request from a fork: GitHub gave it no repository secrets, only a read-only GITHUB_TOKEN")
		rr.Secrets, rr.AllSecrets = nil, false
	}
	return rr, true
}

func possibleSummary(rr RunResult) string {
	switch rr.LogStatus {
	case "expired":
		return "the workflow used the action with a movable ref inside the window; the logs have expired, so this cannot be confirmed or cleared"
	case "not downloaded":
		return "the workflow used the action with a movable ref inside the window; logs were not checked"
	}
	return "the workflow used the action with a movable ref inside the window, and the logs neither prove nor clear it"
}

// fetchEvidence downloads and scans the logs of every attempt of a run.
func fetchEvidence(ctx context.Context, src Source, o Options, repo string, run ghapi.Run) (*logscan.Evidence, string) {
	all := &logscan.Evidence{}
	got, gone := 0, 0
	var errs []string
	for a := 1; a <= max(run.RunAttempt, 1); a++ {
		p, err := src.DownloadRunLogs(ctx, repo, run.ID, a, o.MaxLogBytes)
		if errors.Is(err, ghapi.ErrNotFound) {
			gone++
			continue
		}
		if err != nil {
			errs = append(errs, shortErr(err))
			continue
		}
		ev, err := logscan.ScanZip(p, o.Incident.Indicators)
		_ = os.Remove(p)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		got++
		all.Downloads = append(all.Downloads, ev.Downloads...)
		all.Hits = append(all.Hits, ev.Hits...)
		all.LeakedSecrets = append(all.LeakedSecrets, ev.LeakedSecrets...)
		all.DumpFiles = append(all.DumpFiles, ev.DumpFiles...)
		all.Skipped = append(all.Skipped, ev.Skipped...)
	}
	switch {
	case got > 0 && len(errs) == 0 && gone == 0:
		return all, "scanned"
	case got > 0:
		return all, fmt.Sprintf("partly scanned (%d of %d attempts)", got, max(run.RunAttempt, 1))
	case len(errs) > 0:
		return nil, "error: " + strings.Join(errs, "; ")
	default:
		return nil, "expired"
	}
}

// applyEvidence raises or clears a run's verdict from its logs. Evidence of
// compromise always wins over evidence that clears.
func applyEvidence(rr *RunResult, in incident.Incident, ev *logscan.Evidence) {
	confirmed := false
	cleared, matchedDownload := true, false
	for _, d := range ev.Downloads {
		ref, err := workflow.ParseRef(d.Action)
		if err != nil {
			continue
		}
		for _, t := range in.Targets {
			if !ref.Matches(t.Action) {
				continue
			}
			matchedDownload = true
			v, why, ok := t.AssessResolved(d.SHA)
			if !ok {
				cleared = false
				continue
			}
			if v == incident.Confirmed {
				confirmed = true
				rr.Evidence = append(rr.Evidence, why+" ("+d.File+")")
			} else {
				rr.Evidence = append(rr.Evidence, why)
			}
		}
	}
	for _, h := range ev.Hits {
		confirmed = true
		rr.Evidence = append(rr.Evidence, fmt.Sprintf("indicator %q in the log (%s line %d)", h.Indicator, h.File, h.Line))
	}
	if len(ev.LeakedSecrets) > 0 {
		confirmed = true
		rr.LeakedSecrets = dedupe(ev.LeakedSecrets)
		rr.Evidence = append(rr.Evidence, fmt.Sprintf("the log contains an encoded memory dump with %d secret value(s) in it (%s)", len(rr.LeakedSecrets), strings.Join(dedupe(ev.DumpFiles), ", ")))
	}
	for _, s := range ev.Skipped {
		rr.Reasons = append(rr.Reasons, "part of the log was not scanned: "+s)
	}
	switch {
	case confirmed:
		rr.Verdict = incident.Confirmed
	case matchedDownload && cleared && rr.Verdict == incident.Possible && len(ev.Skipped) == 0:
		rr.Verdict = incident.NotAffected
	}
	rr.Evidence = dedupe(rr.Evidence)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// githubToken is never worth rotating: GitHub revokes it when the job ends.
const githubToken = "GITHUB_TOKEN" //nolint:gosec // a secret NAME, not a credential

// rotation turns affected runs into an ordered list of secrets to rotate.
//
//	critical: the secret's value is in a log (found decoded), or the run is
//	          confirmed in a PUBLIC repository and the payload printed to the
//	          log (anyone could read it)
//	high:     the secret was readable by a confirmed run
//	medium:   the secret was readable by a possible run
func rotation(repos []RepoResult) []Rotation {
	type key struct{ repo, secret string }
	rank := map[string]int{"critical": 3, "high": 2, "medium": 1}
	items := map[key]*Rotation{}
	add := func(repo, secret, prio, why string, run int64) {
		if secret == githubToken {
			return
		}
		k := key{repo, secret}
		it, ok := items[k]
		if !ok {
			it = &Rotation{Repo: repo, Secret: secret, Priority: prio, Why: why}
			items[k] = it
		}
		if rank[prio] > rank[it.Priority] {
			it.Priority, it.Why = prio, why
		}
		for _, r := range it.Runs {
			if r == run {
				return
			}
		}
		it.Runs = append(it.Runs, run)
	}
	for _, repo := range repos {
		for _, run := range repo.Runs {
			if run.Verdict == incident.NotAffected {
				continue
			}
			names := run.Secrets
			if run.AllSecrets {
				names = append(append([]string{}, names...), repo.RepoSecrets...)
				if len(repo.RepoSecrets) == 0 {
					names = append(names, "* (every secret this repository can use)")
				}
			}
			prio, why := "medium", "readable by a run that possibly executed the compromised action"
			if run.Verdict == incident.Confirmed {
				prio, why = "high", "readable by a run confirmed to have executed the compromised action"
				if repo.Visibility == "public" && len(run.LeakedSecrets) > 0 {
					prio, why = "critical", "the run's log is public and contains an encoded memory dump"
				}
			}
			for _, s := range names {
				add(repo.Repo, s, prio, why, run.ID)
			}
			for _, s := range run.LeakedSecrets {
				add(repo.Repo, s, "critical", "its value is printed (encoded) in the run log", run.ID)
			}
		}
	}
	out := make([]Rotation, 0, len(items))
	for _, it := range items {
		sort.Slice(it.Runs, func(i, j int) bool { return it.Runs[i] < it.Runs[j] })
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if rank[a.Priority] != rank[b.Priority] {
			return rank[a.Priority] > rank[b.Priority]
		}
		if a.Repo != b.Repo {
			return a.Repo < b.Repo
		}
		return a.Secret < b.Secret
	})
	return out
}
