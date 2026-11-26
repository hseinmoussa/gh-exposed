package scan

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"errors"
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
	// purged marks repositories whose old run history GitHub has deleted.
	purged    map[string]bool
	commits   map[string]string // repo -> default-branch commit at window end
	branches  map[string]bool   // "owner/repo@name"
	spans     map[string][2]time.Time
	countErr  error
	commitErr error
	tags      map[string]bool
}

func newFake() *fake {
	return &fake{repos: map[string]ghapi.Repo{}, files: map[string]string{}, dirs: map[string][]string{},
		runs: map[string][]ghapi.Run{}, logs: map[string]string{}, secrets: map[string][]string{},
		purged: map[string]bool{}, commits: map[string]string{}, branches: map[string]bool{}, tags: map[string]bool{}, spans: map[string][2]time.Time{}}
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
func (f *fake) CountRunsCreatedBefore(_ context.Context, repo string, _ time.Time) (int, error) {
	if f.countErr != nil {
		return 0, f.countErr
	}
	if f.purged[repo] {
		return 0, nil
	}
	return 1, nil
}
func (f *fake) CommitAt(_ context.Context, repo, _ string, _ time.Time) (string, error) {
	if f.commitErr != nil {
		return "", f.commitErr
	}
	if c, ok := f.commits[repo]; ok {
		return c, nil
	}
	return "", ghapi.ErrNotFound
}
func (f *fake) RefKind(_ context.Context, repo, name string) (bool, bool, error) {
	return f.branches[repo+"@"+name], f.tags[repo+"@"+name], nil
}
func (f *fake) RunJobsSpan(_ context.Context, repo string, id int64) (time.Time, time.Time, error) {
	if sp, ok := f.spans[fmt.Sprintf("%s|%d", repo, id)]; ok {
		return sp[0], sp[1], nil
	}
	return time.Time{}, time.Time{}, ghapi.ErrNotFound
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
	// acme/api is private: a private repository can send secrets to fork
	// pull requests, so the fork run keeps its secrets (with a reason).
	if r := byID[4]; !r.FromFork || !r.AllSecrets || !strings.Contains(strings.Join(r.Reasons, " "), "private repository") {
		t.Errorf("private fork run: %+v", r)
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

func TestPurgedRunHistoryIsNotReportedClean(t *testing.T) {
	f := newFake()
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	f.repos["o/old"] = ghapi.Repo{FullName: "o/old", DefaultBranch: "main", CreatedAt: old, Visibility: "public"}
	f.repos["o/nowf"] = ghapi.Repo{FullName: "o/nowf", DefaultBranch: "main", CreatedAt: old}
	f.repos["o/new"] = ghapi.Repo{FullName: "o/new", DefaultBranch: "main", CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	for _, r := range []string{"o/old", "o/nowf", "o/new"} {
		f.purged[r] = true
	}
	f.commits["o/old"] = "c0ffee"
	f.commits["o/nowf"] = "beef"
	f.dirs["o/old|.github/workflows"] = []string{"ci.yml", "safe.yml", "notes.txt"}
	f.files["o/old|.github/workflows/ci.yml|c0ffee"] = "jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@v44\n        with: { token: '${{ secrets.BOT_PAT }}' }\n"
	f.files["o/old|.github/workflows/safe.yml|c0ffee"] = "jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@" + cleanSHA + "\n"

	rep, err := Run(context.Background(), f, Options{Incident: tj(), Owners: []string{"o"}, Logs: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Worst() != incident.Possible || rep.Summary.PossibleFiles != 1 || rep.Summary.HistoryGaps != 2 {
		t.Fatalf("summary = %+v (o/new was created after the window and must count as complete)", rep.Summary)
	}
	var oldRepo RepoResult
	for _, r := range rep.Repos {
		if r.Repo == "o/old" {
			oldRepo = r
		}
		if r.Repo == "o/new" && !r.HistoryComplete {
			t.Error("a repository created after the window has complete history")
		}
		if r.Repo == "o/nowf" && (len(r.Runs) != 0 || !strings.Contains(strings.Join(r.Notes, " "), "no workflows")) {
			t.Errorf("o/nowf = %+v", r)
		}
	}
	if len(oldRepo.Runs) != 1 {
		t.Fatalf("o/old results = %+v", oldRepo.Runs)
	}
	w := oldRepo.Runs[0]
	if w.Kind != KindWorkflowFile || w.ID != 0 || w.SHA != "c0ffee" || w.Workflow != ".github/workflows/ci.yml" || w.Secrets[0] != "BOT_PAT" {
		t.Errorf("workflow-file result = %+v", w)
	}
	if len(rep.Rotation) != 1 || rep.Rotation[0].Secret != "BOT_PAT" || len(rep.Rotation[0].Runs) != 0 {
		t.Errorf("rotation = %+v", rep.Rotation)
	}
}

// oneRepo builds a fake with one public repository and one workflow.
func oneRepo(wf string) *fake {
	f := newFake()
	f.repos["o/r"] = ghapi.Repo{FullName: "o/r", Visibility: "public"}
	f.files["o/r|.github/workflows/a.yml|s"] = wf
	return f
}

func scanOne(t *testing.T, f Source, o Options) (*Report, RunResult) {
	t.Helper()
	if o.Incident.ID == "" {
		o.Incident = tj()
	}
	o.Repos = []string{"o/r"}
	rep, err := Run(context.Background(), f, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Repos[0].Runs) == 0 {
		return rep, RunResult{}
	}
	return rep, rep.Repos[0].Runs[0]
}

func TestPublicForkRunHasNoSecrets(t *testing.T) {
	f := oneRepo("jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@v1\n        env: { X: '${{ secrets.X }}' }\n")
	r := run(1, ".github/workflows/a.yml", "s")
	r.Event = "pull_request"
	r.HeadRepository = &struct {
		FullName string `json:"full_name"`
	}{FullName: "evil/r"}
	f.runs["o/r"] = []ghapi.Run{r}
	_, got := scanOne(t, f, Options{})
	if len(got.Secrets) != 0 || got.AllSecrets {
		t.Errorf("public fork run must expose no secrets: %+v", got)
	}
}

func TestUnreadableWorkflowIsNotClean(t *testing.T) {
	f := oneRepo("")
	delete(f.files, "o/r|.github/workflows/a.yml|s") // the file cannot be read
	f.runs["o/r"] = []ghapi.Run{run(1, ".github/workflows/a.yml", "s")}
	rep, got := scanOne(t, f, Options{Logs: true})
	if !got.Unassessed || rep.Summary.Unassessed != 1 || !rep.Incomplete() {
		t.Fatalf("an unreadable workflow must be kept as not assessed: %+v %+v", rep.Summary, got)
	}
	// Its log can still confirm it, and then every secret counts.
	f.logs["o/r|1|1"] = "Download action repository 'tj-actions/changed-files@v1' (SHA:" + badSHA + ")\n"
	rep, got = scanOne(t, f, Options{Logs: true})
	if got.Verdict != incident.Confirmed || got.Unassessed || !got.AllSecrets || rep.Incomplete() {
		t.Errorf("log-confirmed unreadable run = %+v", got)
	}
}

func TestFailedAttemptBlocksClearing(t *testing.T) {
	f := oneRepo("jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@v1\n")
	r := run(1, ".github/workflows/a.yml", "s")
	r.RunAttempt = 2
	f.runs["o/r"] = []ghapi.Run{r}
	// attempt 1 expired, attempt 2 shows a clean commit
	f.logs["o/r|1|2"] = "Download action repository 'tj-actions/changed-files@v1' (SHA:" + cleanSHA + ")\n"
	_, got := scanOne(t, f, Options{Logs: true})
	if got.Verdict != incident.Possible {
		t.Errorf("one clean attempt must not clear a run whose other attempt is unreadable: %s %+v", got.Verdict, got.Reasons)
	}
}

func TestRerunOutsideWindowStillCounts(t *testing.T) {
	f := oneRepo("jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@v1\n")
	r := run(1, ".github/workflows/a.yml", "s")
	r.RunAttempt = 2
	r.RunStartedAt = inWindow.Add(10 * 24 * time.Hour) // re-run 10 days later
	r.UpdatedAt = r.RunStartedAt
	f.runs["o/r"] = []ghapi.Run{r}
	_, got := scanOne(t, f, Options{})
	if got.Verdict != incident.Possible {
		t.Errorf("a run whose first attempt was in the window must be flagged: %+v", got)
	}

	// Created 3 hours before a short window and still running inside it.
	rd, _ := incident.Lookup("reviewdog-action-setup-2025")
	f2 := oneRepo("jobs:\n  a:\n    steps:\n      - uses: reviewdog/action-setup@v1\n")
	early := run(2, ".github/workflows/a.yml", "s")
	early.CreatedAt = rd.Start.Add(-3 * time.Hour)
	early.RunStartedAt = early.CreatedAt
	early.UpdatedAt = rd.Start.Add(300 * 24 * time.Hour) // GitHub moves updated_at; it must not decide
	f2.spans["o/r|2"] = [2]time.Time{early.CreatedAt, rd.Start.Add(30 * time.Minute)}
	// A run created before the window whose jobs all ended before it must be
	// left out, even though its updated_at is later.
	before := run(3, ".github/workflows/a.yml", "s")
	before.CreatedAt = rd.Start.Add(-5 * time.Hour)
	before.RunStartedAt = before.CreatedAt
	before.UpdatedAt = rd.Start.Add(300 * 24 * time.Hour)
	f2.spans["o/r|3"] = [2]time.Time{before.CreatedAt, before.CreatedAt.Add(20 * time.Minute)}
	f2.runs["o/r"] = []ghapi.Run{early, before}
	rep2, got := scanOne(t, f2, Options{Incident: rd})
	if got.Verdict != incident.Possible || got.ID != 2 {
		t.Errorf("a run active inside the window must be flagged even if created before it: %+v", got)
	}
	if rep2.Summary.Runs != 1 {
		t.Errorf("the run whose jobs ended before the window must not count: %+v", rep2.Summary)
	}
}

func TestLogOnlyConfirmationListsEveryJobsSecrets(t *testing.T) {
	f := oneRepo("jobs:\n  a:\n    steps:\n      - uses: some/wrapper@" + cleanSHA + "\n        env: { T: '${{ secrets.NPM_TOKEN }}' }\n  b:\n    steps:\n      - run: echo ${{ secrets.OTHER }}\n")
	f.runs["o/r"] = []ghapi.Run{run(1, ".github/workflows/a.yml", "s")}
	f.logs["o/r|1|1"] = "Download action repository 'tj-actions/changed-files@v35' (SHA:" + badSHA + ")\n"
	rep, got := scanOne(t, f, Options{Logs: true, Deep: true})
	if got.Verdict != incident.Confirmed || strings.Join(got.Secrets, ",") != "NPM_TOKEN,OTHER" {
		t.Fatalf("got %+v", got)
	}
	if len(rep.Rotation) != 2 {
		t.Errorf("rotation = %+v", rep.Rotation)
	}
}

func TestSubPathTargetMatchesRepoDownload(t *testing.T) {
	in, err := incident.Custom("own/rep/sub", inWindow.Add(-time.Hour), inWindow.Add(time.Hour), []string{badSHA})
	if err != nil {
		t.Fatal(err)
	}
	f := oneRepo("jobs:\n  a:\n    steps:\n      - uses: own/rep/sub@v1\n")
	f.runs["o/r"] = []ghapi.Run{run(1, ".github/workflows/a.yml", "s")}
	f.logs["o/r|1|1"] = "Download action repository 'own/rep@v1' (SHA:" + badSHA + ")\n"
	_, got := scanOne(t, f, Options{Incident: in, Logs: true})
	if got.Verdict != incident.Confirmed {
		t.Errorf("sub-path target must be confirmed from the repo-level download line: %+v", got)
	}
}

func TestBranchRefClearedWhenOnlyTagsMoved(t *testing.T) {
	f := oneRepo("jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@main\n      - uses: tj-actions/changed-files@both\n")
	f.branches["tj-actions/changed-files@main"] = true
	f.branches["tj-actions/changed-files@both"] = true
	f.tags["tj-actions/changed-files@both"] = true
	f.runs["o/r"] = []ghapi.Run{run(1, ".github/workflows/a.yml", "s")}
	_, got := scanOne(t, f, Options{})
	if got.Verdict != incident.Possible || len(got.Jobs) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got.Jobs[0].Verdict != incident.NotAffected || !strings.Contains(got.Jobs[0].Reason, "branch") {
		t.Errorf("@main (branch only) must be cleared: %+v", got.Jobs[0])
	}
	if got.Jobs[1].Verdict != incident.Possible {
		t.Errorf("@both (branch AND tag) must stay possible: %+v", got.Jobs[1])
	}
}

// flaky fails the first read of one file, then succeeds.
type flaky struct {
	*fake
	failed bool
}

func (f *flaky) GetFile(ctx context.Context, repo, p, ref string) ([]byte, error) {
	if p == "action.yml" && !f.failed {
		f.failed = true
		return nil, errors.New("HTTP 502")
	}
	return f.fake.GetFile(ctx, repo, p, ref)
}

func TestTransientErrorsAreNotCached(t *testing.T) {
	base := oneRepo("jobs:\n  a:\n    steps:\n      - uses: x/wrap@v1\n")
	base.files["x/wrap|action.yml|v1"] = "runs:\n  using: composite\n  steps:\n    - uses: tj-actions/changed-files@v1\n"
	base.runs["o/r"] = []ghapi.Run{run(1, ".github/workflows/a.yml", "s"), run(2, ".github/workflows/a.yml", "s")}
	rep, err := Run(context.Background(), &flaky{fake: base}, Options{Incident: tj(), Repos: []string{"o/r"}, Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Possible != 1 {
		t.Errorf("after one 502, the next run must re-read the file and find the nested action: %+v", rep.Summary)
	}
	if rep.Summary.Unassessed != 1 || !rep.Incomplete() {
		t.Errorf("the run that hit the 502 must be kept as not assessed, not dropped: %+v", rep.Summary)
	}
}

func TestLowercaseGithubTokenIsNotRotated(t *testing.T) {
	got := rotation([]RepoResult{{Repo: "o/r", Runs: []RunResult{{ID: 1, Verdict: incident.Confirmed, LeakedSecrets: []string{"github_token", "REAL"}}}}})
	if len(got) != 1 || got[0].Secret != "REAL" {
		t.Errorf("rotation = %+v", got)
	}
}

func TestRunThatNeverStartedAJobIsCleared(t *testing.T) {
	f := oneRepo("jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@v1\n")
	f.runs["o/r"] = []ghapi.Run{run(1, ".github/workflows/a.yml", "s")}
	f.spans["o/r|1"] = [2]time.Time{} // no jobs
	_, got := scanOne(t, f, Options{})
	if got.Verdict != incident.NotAffected || !strings.Contains(strings.Join(got.Reasons, " "), "never started a job") {
		t.Errorf("got %+v", got)
	}
}

func TestMissingRepoIsAnError(t *testing.T) {
	f := newFake()
	rep, err := Run(context.Background(), f, Options{Incident: tj(), Repos: []string{"o/gone"}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Repos[0].Error != "repository not found, or this token cannot see it" || !rep.Incomplete() {
		t.Errorf("repo = %+v", rep.Repos[0])
	}
}

func purgedRepo() *fake {
	f := newFake()
	f.repos["o/r"] = ghapi.Repo{FullName: "o/r", DefaultBranch: "main", CreatedAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), Visibility: "private"}
	f.purged["o/r"] = true
	f.commits["o/r"] = "c1"
	f.dirs["o/r|.github/workflows"] = []string{"ci.yml"}
	return f
}

func TestFallbackFailuresAreIncomplete(t *testing.T) {
	// The workflow file at the window commit cannot be read.
	f := purgedRepo()
	rep, _ := scanOne(t, f, Options{})
	if !rep.Incomplete() || len(rep.Repos[0].Incomplete) == 0 {
		t.Errorf("unreadable fallback workflow must make the scan incomplete: %+v", rep.Repos[0])
	}
	// The commit lookup fails.
	f = purgedRepo()
	f.commitErr = errors.New("HTTP 502")
	rep, _ = scanOne(t, f, Options{})
	if !rep.Incomplete() {
		t.Errorf("a failed commit lookup must make the scan incomplete: %+v", rep.Repos[0])
	}
	// The history check itself fails: the fallback still runs.
	f = purgedRepo()
	f.purged["o/r"] = false
	f.countErr = errors.New("HTTP 502")
	f.files["o/r|.github/workflows/ci.yml|c1"] = "jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@v44\n"
	rep, _ = scanOne(t, f, Options{})
	if rep.Summary.PossibleFiles != 1 || rep.Repos[0].HistoryComplete {
		t.Errorf("a failed history check must run the fallback: %+v", rep.Summary)
	}
	// A nested action in a fallback file that cannot be read.
	f = purgedRepo()
	f.files["o/r|.github/workflows/ci.yml|c1"] = "jobs:\n  a:\n    steps:\n      - uses: x/wrap@v1\n"
	rep, _ = scanOne(t, &flaky{fake: f}, Options{})
	if !rep.Incomplete() {
		t.Errorf("an unreadable nested action in a fallback file must make the scan incomplete: %+v", rep.Repos[0])
	}
}

func TestFallbackAllSecretsAreListed(t *testing.T) {
	f := purgedRepo()
	f.files["o/r|.github/workflows/ci.yml|c1"] = "jobs:\n  a:\n    secrets: inherit\n    uses: o/r/.github/workflows/b.yml@main\n"
	f.files["o/r|.github/workflows/b.yml|main"] = "jobs:\n  b:\n    steps:\n      - uses: tj-actions/changed-files@v1\n"
	f.secrets["o/r"] = []string{"DEPLOY_KEY"}
	rep, _ := scanOne(t, f, Options{})
	if len(rep.Rotation) != 1 || rep.Rotation[0].Secret != "DEPLOY_KEY" {
		t.Errorf("rotation = %+v", rep.Rotation)
	}
}

func TestRerunOfAnOldRunInsideTheWindow(t *testing.T) {
	f := oneRepo("jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@v1\n")
	r := run(1, ".github/workflows/a.yml", "s")
	r.CreatedAt = inWindow.Add(-5 * 24 * time.Hour) // created 5 days before
	r.RunStartedAt = inWindow                       // re-run inside the window
	r.RunAttempt = 2
	f.runs["o/r"] = []ghapi.Run{r}
	_, got := scanOne(t, f, Options{})
	if got.Verdict != incident.Possible {
		t.Errorf("a re-run inside the window of an older run must be flagged: %+v", got)
	}
	_, got = scanOne(t, f, Options{RerunLookback: 24 * time.Hour})
	if got.Verdict != incident.NotAffected {
		t.Errorf("with a 1-day lookback the 5-day-old run is not listed (documented trade-off): %+v", got)
	}
}
