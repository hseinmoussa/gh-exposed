package scan

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hseinmoussa/gh-exposed/internal/ghapi"
	"github.com/hseinmoussa/gh-exposed/internal/incident"
)

// fake is an in-memory GitHub.
type fake struct {
	mu        sync.Mutex
	repos     map[string]ghapi.Repo
	files     map[string]string // repo|path|ref -> content
	dirs      map[string][]string
	runs      map[string][]ghapi.Run
	logs      map[string]string // repo|runID|attempt -> log text ("" = expired)
	secrets   map[string][]string
	secretErr error
	fileReads int
}

func newFake() *fake {
	return &fake{repos: map[string]ghapi.Repo{}, files: map[string]string{}, dirs: map[string][]string{},
		runs: map[string][]ghapi.Run{}, logs: map[string]string{}, secrets: map[string][]string{}}
}

func (f *fake) GetRepo(_ context.Context, n string) (ghapi.Repo, error) {
	if r, ok := f.repos[n]; ok {
		return r, nil
	}
	return ghapi.Repo{}, ghapi.ErrNotFound
}
func (f *fake) ListRepos(_ context.Context, owner string) ([]ghapi.Repo, error) {
	var out []ghapi.Repo
	for n, r := range f.repos {
		if strings.HasPrefix(n, owner+"/") {
			out = append(out, r)
		}
	}
	return out, nil
}
func (f *fake) GetFile(_ context.Context, repo, p, ref string) ([]byte, error) {
	f.mu.Lock()
	f.fileReads++
	f.mu.Unlock()
	if s, ok := f.files[repo+"|"+p+"|"+ref]; ok {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("%w: %s %s %s", ghapi.ErrNotFound, repo, p, ref)
}
func (f *fake) ListDir(_ context.Context, repo, p, _ string) ([]string, error) {
	if d, ok := f.dirs[repo+"|"+p]; ok {
		return d, nil
	}
	return nil, ghapi.ErrNotFound
}
func (f *fake) ListRuns(_ context.Context, repo string, s, e time.Time) ([]ghapi.Run, error) {
	var out []ghapi.Run
	for _, r := range f.runs[repo] {
		if !r.CreatedAt.Before(s) && !r.CreatedAt.After(e) {
			out = append(out, r)
		}
	}
	return out, nil
}
func (f *fake) DownloadRunLogs(_ context.Context, repo string, id int64, attempt int, _ int64) (string, error) {
	text, ok := f.logs[fmt.Sprintf("%s|%d|%d", repo, id, attempt)]
	if !ok || text == "" {
		return "", ghapi.ErrNotFound
	}
	tmp, err := os.CreateTemp("", "fake-*.zip")
	if err != nil {
		return "", err
	}
	zw := zip.NewWriter(tmp)
	w, _ := zw.Create("build/1_Set up job.txt")
	w.Write([]byte(text))
	zw.Close()
	tmp.Close()
	return tmp.Name(), nil
}
func (f *fake) SecretNames(_ context.Context, repo string) ([]string, error) {
	if f.secretErr != nil {
		return nil, f.secretErr
	}
	return f.secrets[repo], nil
}

const (
	badSHA   = "0e58ed8671d6b60d0890c21b07f8835ace038e67"
	cleanSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var inWindow = time.Date(2025, 3, 14, 17, 0, 0, 0, time.UTC)

func run(id int64, path, sha string) ghapi.Run {
	return ghapi.Run{ID: id, Path: path, HeadSHA: sha, Event: "push", RunAttempt: 1,
		CreatedAt: inWindow, RunStartedAt: inWindow, HTMLURL: fmt.Sprintf("https://github.com/x/runs/%d", id)}
}

func dumpLine(names ...string) string {
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, `{"%s":{"value":"fake-%s","isSecret":true}}`, n, n)
	}
	b.WriteString(strings.Repeat("x", 100))
	once := base64.StdEncoding.EncodeToString([]byte(b.String()))
	return base64.StdEncoding.EncodeToString([]byte(once))
}

func tj() incident.Incident {
	in, _ := incident.Lookup("tj-actions-changed-files-2025")
	return in
}

func TestScanEndToEnd(t *testing.T) {
	f := newFake()
	f.repos["acme/web"] = ghapi.Repo{FullName: "acme/web", Visibility: "public"}
	f.repos["acme/api"] = ghapi.Repo{FullName: "acme/api", Visibility: "private"}
	f.repos["acme/lib"] = ghapi.Repo{FullName: "acme/lib", Visibility: "private"}

	// acme/web: tag-pinned, logs show the malicious commit and a dump.
	f.files["acme/web|.github/workflows/ci.yml|s1"] = `
env:
  SHARED: ${{ secrets.SHARED }}
jobs:
  changes:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@v45
        with: { token: "${{ secrets.GH_PAT }}" }
  other:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.UNRELATED }}
`
	f.runs["acme/web"] = []ghapi.Run{run(1, ".github/workflows/ci.yml", "s1")}
	f.logs["acme/web|1|1"] = "Download action repository 'tj-actions/changed-files@v45' (SHA:" + badSHA + ")\n" + dumpLine("GH_PAT", "SHARED")

	// acme/api: reached through a local composite action; one run's logs
	// expired, a second run's logs show a clean commit, a third run is a
	// fork PR, a fourth is SHA-pinned clean, a fifth is outside the window.
	f.files["acme/api|.github/workflows/build.yml|s2"] = `
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/setup
      - run: echo ${{ toJSON(secrets) }}
`
	f.files["acme/api|.github/actions/setup/action.yml|s2"] = `
runs:
  using: composite
  steps:
    - uses: tj-actions/changed-files@main
`
	f.files["acme/api|.github/workflows/pinned.yml|s2"] = `
jobs:
  p:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@` + cleanSHA + `
`
	expired := run(2, ".github/workflows/build.yml", "s2")
	clean := run(3, ".github/workflows/build.yml", "s2")
	fork := run(4, ".github/workflows/build.yml", "s2")
	fork.Event = "pull_request"
	fork.HeadRepository = &struct {
		FullName string `json:"full_name"`
	}{FullName: "attacker/api"}
	pinned := run(5, ".github/workflows/pinned.yml", "s2")
	late := run(6, ".github/workflows/build.yml", "s2")
	late.CreatedAt = inWindow.Add(72 * time.Hour)
	late.RunStartedAt = late.CreatedAt
	f.runs["acme/api"] = []ghapi.Run{expired, clean, fork, pinned, late}
	f.logs["acme/api|3|1"] = "Download action repository 'tj-actions/changed-files@main' (SHA:" + cleanSHA + ")\n"
	f.secrets["acme/api"] = []string{"DB_URL", "NPM_TOKEN"}

	// acme/lib: no runs in the window at all.

	rep, err := Run(context.Background(), f, Options{Incident: tj(), Owners: []string{"acme"}, Logs: true})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[int64]RunResult{}
	for _, r := range rep.Repos {
		for _, x := range r.Runs {
			byID[x.ID] = x
		}
	}
	if v := byID[1].Verdict; v != incident.Confirmed {
		t.Errorf("run 1 = %s, want confirmed", v)
	}
	if got := strings.Join(byID[1].LeakedSecrets, ","); got != "GH_PAT,SHARED" {
		t.Errorf("run 1 leaked = %s", got)
	}
	if got := strings.Join(byID[1].Secrets, ","); got != "GH_PAT,SHARED" {
		t.Errorf("run 1 secrets = %s (UNRELATED is in another job and must not appear)", got)
	}
	if r := byID[2]; r.Verdict != incident.Possible || r.LogStatus != "expired" || !r.AllSecrets {
		t.Errorf("run 2 = %+v", r)
	}
	if len(byID[2].Jobs) != 1 || len(byID[2].Jobs[0].Chain) != 2 {
		t.Errorf("run 2 must be reached through the composite (2-link chain): %+v", byID[2].Jobs)
	}
	if v := byID[3].Verdict; v != incident.NotAffected {
		t.Errorf("run 3 = %s, want cleared by its log", v)
	}
	if r := byID[4]; !r.FromFork || r.AllSecrets || len(r.Secrets) != 0 {
		t.Errorf("fork run must expose no secrets: %+v", r)
	}
	if v := byID[5].Verdict; v != incident.NotAffected {
		t.Errorf("run 5 (clean SHA pin) = %s", v)
	}
	if _, ok := byID[6]; ok {
		t.Error("run 6 is outside the window and must not be listed")
	}
	if rep.Summary.Repos != 3 || rep.Summary.Confirmed != 1 || rep.Worst() != incident.Confirmed {
		t.Errorf("summary = %+v", rep.Summary)
	}

	// Rotation: public + dump = critical first; toJSON(secrets) expands to
	// the repository's secret names; GITHUB_TOKEN never appears.
	if len(rep.Rotation) == 0 || rep.Rotation[0].Priority != "critical" || rep.Rotation[0].Repo != "acme/web" {
		t.Fatalf("rotation = %+v", rep.Rotation)
	}
	var apiSecrets []string
	for _, r := range rep.Rotation {
		if r.Secret == "GITHUB_TOKEN" {
			t.Error("GITHUB_TOKEN must not be listed for rotation")
		}
		if r.Repo == "acme/api" {
			apiSecrets = append(apiSecrets, r.Secret+":"+r.Priority)
		}
	}
	if got := strings.Join(apiSecrets, ","); got != "DB_URL:medium,NPM_TOKEN:medium" {
		t.Errorf("api rotation = %s", got)
	}
	// Reports must never carry a secret value.
	if s := fmt.Sprintf("%+v", rep); strings.Contains(s, "fake-GH_PAT") {
		t.Fatal("secret value leaked into the report")
	}
}

func TestDeepFindsWhatFilesHide(t *testing.T) {
	f := newFake()
	f.repos["o/r"] = ghapi.Repo{FullName: "o/r", Visibility: "private"}
	// The workflow names no compromised action, but the log shows the
	// malicious commit downloaded (reached through a now-cleaned action).
	f.files["o/r|.github/workflows/a.yml|s"] = "jobs:\n  a:\n    steps:\n      - uses: some/wrapper@v1\n"
	f.runs["o/r"] = []ghapi.Run{run(9, ".github/workflows/a.yml", "s")}
	f.logs["o/r|9|1"] = "Download action repository 'tj-actions/changed-files@v35' (SHA:" + badSHA + ")\n"

	rep, err := Run(context.Background(), f, Options{Incident: tj(), Repos: []string{"o/r"}, Logs: true})
	if err != nil || rep.Summary.Confirmed != 0 {
		t.Fatalf("without --deep the run is not flagged: %+v %v", rep.Summary, err)
	}
	rep, err = Run(context.Background(), f, Options{Incident: tj(), Repos: []string{"o/r"}, Logs: true, Deep: true})
	if err != nil || rep.Summary.Confirmed != 1 {
		t.Fatalf("with --deep the run is confirmed: %+v %v", rep.Summary, err)
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), "no action.yml found for some/wrapper") {
		t.Errorf("notes must record the unreadable wrapper: %v", rep.Notes)
	}
}

func TestSecretListingDeniedIsReported(t *testing.T) {
	f := newFake()
	f.repos["o/r"] = ghapi.Repo{FullName: "o/r", Private: true}
	f.files["o/r|.github/workflows/a.yml|s"] = "jobs:\n  a:\n    secrets: inherit\n    uses: o/r/.github/workflows/b.yml@main\n"
	f.files["o/r|.github/workflows/b.yml|main"] = "jobs:\n  b:\n    steps:\n      - uses: tj-actions/changed-files@v1\n"
	f.runs["o/r"] = []ghapi.Run{run(1, ".github/workflows/a.yml", "s")}
	f.secretErr = ghapi.ErrForbidden

	rep, err := Run(context.Background(), f, Options{Incident: tj(), Repos: []string{"o/r"}})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Repos[0]
	if r.Visibility != "private" || len(r.Runs) != 1 || r.Runs[0].Verdict != incident.Possible || r.Runs[0].LogStatus != "not downloaded" {
		t.Fatalf("repo = %+v", r)
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "permission denied") {
		t.Errorf("notes = %v", r.Notes)
	}
	if len(rep.Rotation) != 1 || !strings.HasPrefix(rep.Rotation[0].Secret, "*") {
		t.Errorf("rotation must say every secret: %+v", rep.Rotation)
	}
}

func TestCyclesAndCaching(t *testing.T) {
	f := newFake()
	f.repos["o/r"] = ghapi.Repo{FullName: "o/r"}
	// Two composites that call each other must not loop forever.
	f.files["o/r|.github/workflows/a.yml|s"] = "jobs:\n  a:\n    steps:\n      - uses: x/one@v1\n      - uses: x/one@v1\n"
	f.files["x/one|action.yml|v1"] = "runs:\n  using: composite\n  steps:\n    - uses: x/two@v1\n"
	f.files["x/two|action.yml|v1"] = "runs:\n  using: composite\n  steps:\n    - uses: x/one@v1\n    - uses: tj-actions/changed-files@v2\n"
	var runs []ghapi.Run
	for i := int64(1); i <= 20; i++ {
		runs = append(runs, run(i, ".github/workflows/a.yml", "s"))
	}
	f.runs["o/r"] = runs
	rep, err := Run(context.Background(), f, Options{Incident: tj(), Repos: []string{"o/r"}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Possible != 20 {
		t.Errorf("possible = %d, want 20", rep.Summary.Possible)
	}
	if f.fileReads > 6 {
		t.Errorf("files read %d times; the resolver must cache", f.fileReads)
	}
}

func TestMissingRepoAndDynamicWorkflow(t *testing.T) {
	f := newFake()
	f.repos["o/r"] = ghapi.Repo{FullName: "o/r"}
	dyn := run(1, "dynamic/github-code-scanning/codeql", "s")
	f.runs["o/r"] = []ghapi.Run{dyn}
	rep, err := Run(context.Background(), f, Options{Incident: tj(), Repos: []string{"o/r", "o/missing"}, Logs: true, Deep: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Repos != 2 || rep.Summary.Runs != 1 {
		t.Errorf("summary = %+v", rep.Summary)
	}
	if _, err := Run(context.Background(), f, Options{Incident: tj()}); err == nil {
		t.Error("want error with no repositories")
	}
}

func TestUsage(t *testing.T) {
	f := newFake()
	f.repos["o/r"] = ghapi.Repo{FullName: "o/r"}
	f.repos["o/empty"] = ghapi.Repo{FullName: "o/empty"}
	f.dirs["o/r|.github/workflows"] = []string{"ci.yml", "README.md"}
	f.files["o/r|.github/workflows/ci.yml|"] = "jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@v45\n      - uses: ./local\n"
	f.files["o/r|local/action.yml|"] = "runs:\n  using: composite\n  steps:\n    - uses: tj-actions/changed-files@" + cleanSHA + "\n"
	rep, err := Usage(context.Background(), f, "tj-actions/changed-files", nil, []string{"o"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Repos != 2 || len(rep.Rows) != 2 {
		t.Fatalf("usage = %+v", rep)
	}
	if !rep.Rows[0].Direct || rep.Rows[0].Pin != "mutable" || rep.Rows[1].Direct || rep.Rows[1].Pin != "sha" {
		t.Errorf("rows = %+v", rep.Rows)
	}
}
