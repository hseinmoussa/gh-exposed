package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hseinmoussa/gh-exposed/internal/ghapi"
	"github.com/hseinmoussa/gh-exposed/internal/scan"
)

// stub is a minimal Source: one repository whose single run in the
// tj-actions window used the action by tag, with expired logs.
type stub struct{ gotToken string }

func (s *stub) GetRepo(_ context.Context, n string) (ghapi.Repo, error) {
	return ghapi.Repo{FullName: n, Visibility: "private"}, nil
}
func (s *stub) ListRepos(context.Context, string) ([]ghapi.Repo, error) {
	return []ghapi.Repo{{FullName: "acme/web"}}, nil
}
func (s *stub) GetFile(_ context.Context, _, p, _ string) ([]byte, error) {
	if p == ".github/workflows/ci.yml" {
		return []byte("jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@v45\n        env: { T: '${{ secrets.DEPLOY_KEY }}' }\n"), nil
	}
	return nil, ghapi.ErrNotFound
}
func (s *stub) ListDir(context.Context, string, string, string) ([]string, error) {
	return []string{"ci.yml"}, nil
}
func (s *stub) ListRuns(_ context.Context, _ string, start, end time.Time) ([]ghapi.Run, error) {
	at := time.Date(2025, 3, 14, 12, 0, 0, 0, time.UTC)
	if at.Before(start) || at.After(end) {
		return nil, nil
	}
	return []ghapi.Run{{ID: 42, Path: ".github/workflows/ci.yml", HeadSHA: "s", Event: "push", RunAttempt: 1, CreatedAt: at}}, nil
}
func (s *stub) DownloadRunLogs(context.Context, string, int64, int, int64) (string, error) {
	return "", ghapi.ErrNotFound
}
func (s *stub) SecretNames(context.Context, string) ([]string, error) { return nil, nil }
func (s *stub) CountRunsCreatedBefore(context.Context, string, time.Time) (int, error) {
	return 1, nil
}
func (s *stub) RefKind(context.Context, string, string) (bool, bool, error) {
	return false, true, nil
}
func (s *stub) RunJobsSpan(context.Context, string, int64) (time.Time, time.Time, error) {
	return time.Time{}, time.Time{}, ghapi.ErrNotFound
}
func (s *stub) CommitAt(context.Context, string, string, time.Time) (string, error) {
	return "", ghapi.ErrNotFound
}

func testEnv(env map[string]string) (Env, *bytes.Buffer, *bytes.Buffer, *stub) {
	var out, errb bytes.Buffer
	st := &stub{}
	return Env{
		Stdout: &out, Stderr: &errb,
		Getenv:    func(k string) string { return env[k] },
		NewSource: func(_, tok string) scan.Source { st.gotToken = tok; return st },
		GHToken:   func() (string, error) { return "", errors.New("gh not installed") },
		Now:       func() time.Time { return time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC) },
	}, &out, &errb, st
}

func TestScanBuiltinIncident(t *testing.T) {
	env, out, _, st := testEnv(map[string]string{"GH_TOKEN": "t1", "GITHUB_TOKEN": "t2"})
	code := Main(context.Background(), []string{"scan", "--incident", "tj-actions-changed-files-2025", "--repo", "acme/web"}, env)
	if code != ExitPossible {
		t.Fatalf("exit = %d, want %d; out=%s", code, ExitPossible, out)
	}
	if st.gotToken != "t1" {
		t.Errorf("GH_TOKEN must win over GITHUB_TOKEN, got %q", st.gotToken)
	}
	s := out.String()
	for _, want := range []string{"POSSIBLE", "run 42", "DEPLOY_KEY", "MEDIUM", "logs: expired", "GHSA-mrrh-fwg8-r2c3"} {
		if !strings.Contains(s, want) {
			t.Errorf("text report missing %q:\n%s", want, s)
		}
	}
}

func TestScanFormatsAndFailOn(t *testing.T) {
	env, out, _, _ := testEnv(map[string]string{"GITHUB_TOKEN": "t"})
	code := Main(context.Background(), []string{"scan", "--incident", "tj-actions-changed-files-2025", "--owner", "acme", "--format", "json", "--fail-on", "confirmed"}, env)
	if code != ExitOK {
		t.Fatalf("fail-on confirmed with only possible runs: exit %d", code)
	}
	var rep scan.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("json output does not parse: %v\n%s", err, out)
	}
	if rep.Summary.Possible != 1 || rep.Repos[0].Runs[0].Verdict.String() != "possible" {
		t.Errorf("json = %+v", rep.Summary)
	}
	if !strings.Contains(out.String(), `"verdict": "possible"`) {
		t.Error("verdicts must render as names in JSON")
	}

	env, out, _, _ = testEnv(map[string]string{"GITHUB_TOKEN": "t"})
	if code := Main(context.Background(), []string{"scan", "--incident", "tj-actions-changed-files-2025", "--repo", "acme/web", "--format", "md"}, env); code != ExitPossible {
		t.Fatalf("markdown exit %d", code)
	}
	if !strings.Contains(out.String(), "| Priority | Repository |") || !strings.Contains(out.String(), "`DEPLOY_KEY`") {
		t.Errorf("markdown report:\n%s", out)
	}
}

func TestScanCustomActionAndOutFile(t *testing.T) {
	env, out, errb, _ := testEnv(map[string]string{"GH_TOKEN": "t"})
	p := filepath.Join(t.TempDir(), "r.md")
	code := Main(context.Background(), []string{"scan", "--action", "tj-actions/changed-files", "--since", "2025-03-14", "--until", "2025-03-14", "--repo", "acme/web", "--no-logs", "--format", "markdown", "--out", p}, env)
	if code != ExitPossible {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if out.Len() != 0 {
		t.Error("with --out nothing goes to stdout")
	}
	b, err := os.ReadFile(p)
	if err != nil || !strings.Contains(string(b), "logs: not downloaded") {
		t.Errorf("report file: %v\n%s", err, b)
	}
	// Windows has no Unix permission bits; os.Stat reports 0666 there.
	if fi, _ := os.Stat(p); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("report file mode = %v, want 0600 (it names secrets)", fi.Mode().Perm())
	}
}

func TestUsageErrors(t *testing.T) {
	cases := map[string][]string{
		"no command":           {},
		"unknown command":      {"nope"},
		"no target":            {"scan", "--incident", "tj-actions-changed-files-2025"},
		"bad repo":             {"scan", "--incident", "tj-actions-changed-files-2025", "--repo", "acme"},
		"unknown incident":     {"scan", "--incident", "nope", "--repo", "a/b"},
		"incident and action":  {"scan", "--incident", "tj-actions-changed-files-2025", "--action", "a/b", "--repo", "a/b"},
		"action without since": {"scan", "--action", "a/b", "--repo", "a/b"},
		"bad date":             {"scan", "--action", "a/b", "--since", "yesterday", "--until", "2025-01-01", "--repo", "a/b"},
		"reversed window":      {"scan", "--action", "a/b", "--since", "2025-02-01", "--until", "2025-01-01", "--repo", "a/b"},
		"short sha":            {"scan", "--action", "a/b", "--since", "2025-01-01", "--until", "2025-01-02", "--malicious-sha", "abc", "--repo", "a/b"},
		"bad format":           {"scan", "--incident", "tj-actions-changed-files-2025", "--repo", "a/b", "--format", "xml"},
		"bad fail-on":          {"scan", "--incident", "tj-actions-changed-files-2025", "--repo", "a/b", "--fail-on", "always"},
		"deep and no-logs":     {"scan", "--incident", "tj-actions-changed-files-2025", "--repo", "a/b", "--deep", "--no-logs"},
		"stray argument":       {"scan", "--incident", "tj-actions-changed-files-2025", "--repo", "a/b", "extra"},
		"bad concurrency":      {"scan", "--incident", "tj-actions-changed-files-2025", "--repo", "a/b", "--concurrency", "0"},
		"usage no action":      {"usage", "--repo", "a/b"},
		"unknown flag":         {"scan", "--bogus"},
	}
	for name, args := range cases {
		env, _, _, _ := testEnv(map[string]string{"GH_TOKEN": "t"})
		if code := Main(context.Background(), args, env); code != ExitUsage {
			t.Errorf("%s: exit %d, want %d", name, code, ExitUsage)
		}
	}
}

func TestNoTokenIsAnError(t *testing.T) {
	env, _, errb, _ := testEnv(nil)
	code := Main(context.Background(), []string{"scan", "--incident", "tj-actions-changed-files-2025", "--repo", "a/b"}, env)
	if code != ExitError || !strings.Contains(errb.String(), "gh auth login") {
		t.Errorf("exit %d: %s", code, errb)
	}
}

func TestUsageCommandAndIncidents(t *testing.T) {
	env, out, _, _ := testEnv(map[string]string{"GH_TOKEN": "t"})
	if code := Main(context.Background(), []string{"usage", "--action", "tj-actions/changed-files", "--repo", "acme/web"}, env); code != ExitOK {
		t.Fatalf("usage exit %d", code)
	}
	if !strings.Contains(out.String(), "tj-actions/changed-files@v45") || !strings.Contains(out.String(), "Pin to a full commit SHA") {
		t.Errorf("usage output:\n%s", out)
	}
	env, out, _, _ = testEnv(nil)
	if code := Main(context.Background(), []string{"incidents"}, env); code != ExitOK || !strings.Contains(out.String(), "trivy-action-2026") {
		t.Errorf("incidents: %d\n%s", code, out)
	}
	env, out, _, _ = testEnv(nil)
	if code := Main(context.Background(), []string{"version"}, env); code != ExitOK || !strings.HasPrefix(out.String(), "gh-exposed ") {
		t.Errorf("version: %s", out)
	}
	env, _, _, _ = testEnv(nil)
	if code := Main(context.Background(), []string{"scan", "-h"}, env); code != ExitOK {
		t.Errorf("-h exit %d", code)
	}
}

func TestParseTime(t *testing.T) {
	end, _ := parseTime("2025-03-15", true)
	if !end.Equal(time.Date(2025, 3, 16, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("date --until must mean end of day, got %s", end)
	}
	exact, _ := parseTime("2025-03-11T18:42:00+02:00", true)
	if !exact.Equal(time.Date(2025, 3, 11, 16, 42, 0, 0, time.UTC)) {
		t.Errorf("RFC 3339 must be exact and UTC, got %s", exact)
	}
}
