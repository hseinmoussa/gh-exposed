package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hseinmoussa/gh-exposed/internal/incident"
	"github.com/hseinmoussa/gh-exposed/internal/scan"
)

func sample() *scan.Report {
	in, _ := incident.Lookup("tj-actions-changed-files-2025")
	return &scan.Report{
		Tool: "gh-exposed", Generated: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Incident: in,
		Summary: scan.Summary{Repos: 2, Runs: 3, Confirmed: 1, Possible: 1},
		Repos: []scan.RepoResult{{
			Repo: "acme/web", Visibility: "public", RunsInWindow: 3,
			Runs: []scan.RunResult{
				{ID: 2, Verdict: incident.Possible, Workflow: ".github/workflows/a.yml", LogStatus: "expired", AllSecrets: true},
				{ID: 1, Verdict: incident.Confirmed, Workflow: ".github/workflows/ci.yml", Event: "push", Branch: "main",
					Evidence: []string{"the run log shows the runner downloaded the malicious commit 0e58ed8671d6"},
					Jobs:     []scan.JobHit{{Job: "build", Action: "tj-actions/changed-files@v45", Reason: "movable", Chain: []scan.Link{{File: "ci.yml", Line: 7}}}},
					Secrets:  []string{"NPM_TOKEN"}, LeakedSecrets: []string{"NPM_TOKEN"}, LogStatus: "scanned"},
			},
			Notes: []string{"a note with a | pipe"},
		}},
		Rotation: []scan.Rotation{{Repo: "acme/web", Secret: "NPM_TOKEN", Priority: "critical", Why: "value | in log", Runs: []int64{1, 2, 3, 4, 5, 6, 7}}},
	}
}

func TestScanFormats(t *testing.T) {
	for _, f := range []Format{Text, Markdown, JSON} {
		var b bytes.Buffer
		if err := Scan(&b, f, sample()); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		s := b.String()
		if !strings.Contains(s, "NPM_TOKEN") || !strings.Contains(s, "GHSA-mrrh-fwg8-r2c3") {
			t.Errorf("%s output missing content:\n%s", f, s)
		}
		if f == Text && strings.Index(s, "CONFIRMED  run 1") > strings.Index(s, "POSSIBLE  run 2") {
			t.Errorf("confirmed runs must be listed first:\n%s", s)
		}
		if f == Markdown {
			if !strings.Contains(s, `value \| in log`) {
				t.Errorf("markdown must escape pipes in table cells:\n%s", s)
			}
			if !strings.Contains(s, "+2 more") {
				t.Error("long run lists must be shortened")
			}
		}
	}
}

func TestNothingFound(t *testing.T) {
	r := sample()
	r.Summary = scan.Summary{Repos: 1}
	r.Repos, r.Rotation = nil, nil
	var b bytes.Buffer
	if err := Scan(&b, Text, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "No run in the scanned repositories executed the compromised code") || strings.Contains(b.String(), "SECRETS TO ROTATE") {
		t.Errorf("clean report:\n%s", b.String())
	}
}

type failWriter struct{ n int }

func (f *failWriter) Write(p []byte) (int, error) {
	f.n++
	if f.n > 2 {
		return 0, errors.New("disk full")
	}
	return len(p), nil
}

func TestWriteErrorsAreReturned(t *testing.T) {
	if err := Scan(&failWriter{}, Text, sample()); err == nil || err.Error() != "disk full" {
		t.Errorf("Scan: want disk full, got %v", err)
	}
	if err := Usage(&failWriter{}, Text, &scan.UsageReport{Action: "a/b", Rows: []scan.UsageRow{{Repo: "r", Chain: []scan.Link{{}}}}}); err == nil {
		t.Error("Usage: want error")
	}
	if err := Incidents(&failWriter{}, Text, incident.Builtin()); err == nil {
		t.Error("Incidents: want error")
	}
}

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]Format{"": Text, "TEXT": Text, "md": Markdown, "markdown": Markdown, "json": JSON} {
		if got, err := ParseFormat(in); err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %s, %v", in, got, err)
		}
	}
	if _, err := ParseFormat("yaml"); err == nil {
		t.Error("want error")
	}
}

func TestHistoryGapRendering(t *testing.T) {
	r := sample()
	r.Summary = scan.Summary{Repos: 1, HistoryGaps: 1, PossibleFiles: 1}
	r.Repos[0].Runs = []scan.RunResult{{Kind: scan.KindWorkflowFile, Workflow: ".github/workflows/ci.yml", Branch: "main",
		SHA: "c0ffeec0ffeec0ffee", Verdict: incident.Possible, LogStatus: "no run history", Secrets: []string{"BOT_PAT"}}}
	var b bytes.Buffer
	if err := Scan(&b, Text, r); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{"workflow .github/workflows/ci.yml  on main at c0ffeec0ffee  (no run history)", "1 workflow file(s)", "Repos without run history"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "run 0") {
		t.Error("a workflow-file result must not print as run 0")
	}
	r.Repos[0].Runs = nil
	r.Summary.PossibleFiles = 0
	b.Reset()
	_ = Scan(&b, Text, r)
	if !strings.Contains(b.String(), "not a complete answer") {
		t.Errorf("a clean result with history gaps must say it is incomplete:\n%s", b.String())
	}
}
