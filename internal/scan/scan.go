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
	// Kind is KindRun for a real workflow run, or KindWorkflowFile for a
	// workflow file judged without a run (the run history is gone); a
	// workflow-file result has no ID, event or start time.
	Kind      string           `json:"kind"`
	ID        int64            `json:"id,omitempty"`
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
	// Unassessed: the workflow file could not be read, so the run could be
	// neither cleared nor flagged from it.
	Unassessed bool     `json:"unassessed,omitempty"`
	LogStatus  string   `json:"log_status"`
	Evidence   []string `json:"evidence,omitempty"`
}

// Result kinds.
const (
	KindRun          = "run"
	KindWorkflowFile = "workflow_file"
)

// RepoResult is one scanned repository.
type RepoResult struct {
	Repo         string `json:"repo"`
	Visibility   string `json:"visibility"`
	RunsInWindow int    `json:"runs_in_window"`
	// HistoryComplete is false when GitHub no longer lists runs from before
	// the window: an empty run list then proves nothing.
	HistoryComplete bool        `json:"history_complete"`
	Runs            []RunResult `json:"runs,omitempty"`
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
	// HistoryGaps counts repositories whose run history does not reach the
	// window; PossibleFiles counts workflow files flagged in them.
	HistoryGaps   int `json:"repos_without_run_history"`
	Unassessed    int `json:"runs_not_assessed"`
	PossibleFiles int `json:"workflow_files_possible"`
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

// Incomplete reports whether part of the scan failed, so "nothing found"
// must not be read as "nothing happened".
func (r *Report) Incomplete() bool {
	return r.Summary.RepoErrs > 0 || r.Summary.Unassessed > 0
}

// Worst returns the most severe verdict in the report.
func (r *Report) Worst() incident.Verdict {
	switch {
	case r.Summary.Confirmed > 0:
		return incident.Confirmed
	case r.Summary.Possible > 0 || r.Summary.PossibleFiles > 0:
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
		if !r.HistoryComplete && r.Error == "" {
			rep.Summary.HistoryGaps++
		}
		for _, run := range r.Runs {
			if run.Kind == KindWorkflowFile {
				rep.Summary.PossibleFiles++
				continue
			}
			if run.Unassessed {
				rep.Summary.Unassessed++
			}
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
	// A run created shortly before the window can still be executing inside
	// it (a long job, a job waiting on `needs:`), so the listing starts a day
	// early and each run is then kept only if its active time overlaps.
	listed, err := src.ListRuns(ctx, repo.FullName, start.Add(-runLead), end)
	if err != nil {
		out.Error = "list runs: " + ghapi.RedactText(err.Error())
		return out
	}
	var runs []ghapi.Run
	spans := map[int64]activeSpan{}
	spanUnknown := 0
	for _, r := range listed {
		from, to := runActive(r)
		if to.Before(start) && r.CreatedAt.Before(start) {
			// Created before the window: did any job still run inside it?
			// Only the jobs know; the run's updated_at cannot be trusted.
			_, last, err := src.RunJobsSpan(ctx, repo.FullName, r.ID)
			switch {
			case err != nil:
				spanUnknown++
				to = r.UpdatedAt // cautious: include it if it might overlap
			case last.After(to):
				to = last
			}
		}
		if !from.After(end) && !to.Before(start) {
			runs = append(runs, r)
			spans[r.ID] = activeSpan{from, to}
		}
	}
	if spanUnknown > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf("%d run(s) created before the window had no readable job times; they were included if they might overlap it", spanUnknown))
	}
	out.RunsInWindow = len(runs)
	out.HistoryComplete = true
	// A repository created after the window started cannot have older runs,
	// so its listing is complete by definition. Otherwise ask whether GitHub
	// still lists ANY run from before the window.
	if repo.CreatedAt.IsZero() || repo.CreatedAt.Before(start) {
		n, err := src.CountRunsCreatedBefore(ctx, repo.FullName, start)
		switch {
		case err != nil:
			out.Notes = append(out.Notes, "could not check how far back the run history goes ("+shortErr(err)+"); an empty result may be incomplete")
		case n == 0:
			out.HistoryComplete = false
			out.Notes = append(out.Notes, "GitHub lists no run of this repository from before the window, so runs inside it may have been deleted; its workflows from the window were checked instead")
			files, note := historyFallback(ctx, src, res, in, repo, end)
			out.Runs = append(out.Runs, files...)
			if note != "" {
				out.Notes = append(out.Notes, note)
			}
		}
	}

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
		span := spans[run.ID]
		go func(i int, run ghapi.Run) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			rr, keep := scanRun(ctx, src, res, o, repo, run, span)
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

// runLead is how long before the window runs are listed: a run created then
// may still have been executing when the window opened.
const runLead = 24 * time.Hour

// runActive returns the span a run is known to have been active from its own
// timestamps: creation (when attempt 1 began) to the latest attempt's start.
// run_started_at alone is not enough, because a re-run resets it and would
// hide a first attempt that ran inside the window. updated_at is NOT used:
// GitHub moves it months after a run finished. A run created before the
// window has its real end read from its jobs (see scanRepo).
func runActive(r ghapi.Run) (time.Time, time.Time) {
	var from, to time.Time
	for _, t := range []time.Time{r.RunStartedAt, r.CreatedAt} {
		if t.IsZero() {
			continue
		}
		if from.IsZero() || t.Before(from) {
			from = t
		}
		if t.After(to) {
			to = t
		}
	}
	return from, to
}

func runStart(r ghapi.Run) time.Time {
	if !r.RunStartedAt.IsZero() {
		return r.RunStartedAt
	}
	return r.CreatedAt
}

// scanRun assesses one run. keep is false for a run that never reached a
// compromised action (it is counted, not listed).
// span is when the run was active, as worked out by scanRepo.
func scanRun(ctx context.Context, src Source, res *resolver, o Options, repo ghapi.Repo, run ghapi.Run, span activeSpan) (RunResult, bool) {
	in := o.Incident
	rr := RunResult{
		Kind: KindRun, ID: run.ID, Attempts: max(run.RunAttempt, 1), URL: run.HTMLURL, Workflow: run.Path,
		Event: run.Event, Branch: run.HeadBranch, SHA: run.HeadSHA, StartedAt: runStart(run),
		FromFork: run.FromFork(repo.FullName), LogStatus: "not downloaded",
	}

	// 1. Static assessment from the workflow file at the commit that ran.
	var st static
	switch {
	case strings.HasPrefix(run.Path, ".github/workflows/"):
		st = assessWorkflow(ctx, res, in, repo.FullName, run.Path, run.HeadSHA, &span)
		rr.Jobs, rr.Verdict = st.jobs, st.verdict
		if st.err != "" {
			// Not knowing is not the same as clean: keep the run, try its
			// logs, and count it so the result is reported as incomplete.
			rr.Unassessed = true
			rr.Reasons = append(rr.Reasons, st.err)
		}
	case run.Path != "":
		rr.Reasons = append(rr.Reasons, "run of "+run.Path+" has no workflow file in the repository (a GitHub-managed workflow); only its logs can show what ran")
	}
	staticHit := len(rr.Jobs) > 0

	// 2. Log evidence.
	wantLogs := o.Logs && (rr.Verdict == incident.Possible || o.Deep || rr.Unassessed)
	if wantLogs {
		ev, status := fetchEvidence(ctx, src, o, repo.FullName, run)
		rr.LogStatus = status
		if ev != nil {
			applyEvidence(&rr, in, ev)
		}
	}
	if rr.Verdict == incident.Confirmed {
		rr.Unassessed = false
	}
	if !staticHit && !rr.Unassessed && rr.Verdict == incident.NotAffected && len(rr.Evidence) == 0 {
		return rr, false
	}

	if rr.Verdict == incident.Possible {
		rr.Reasons = append([]string{possibleSummary(rr)}, rr.Reasons...)
	}

	// 3. Secrets the exposed code could read.
	secrets, all := st.secrets, st.allSecrets
	if rr.Verdict == incident.Confirmed && !st.anyJobHit {
		// Only the log proved it, and the log does not map back to a job id,
		// so every job's secrets count. With no readable workflow at all,
		// every secret does.
		if st.err != "" || st.everySecret == nil {
			all = true
		} else {
			secrets, all = st.everySecret, st.everyAll
		}
		rr.Reasons = append(rr.Reasons, "the log does not say which job ran the compromised code, so the secrets of every job in the workflow are listed")
	}
	for s := range secrets {
		rr.Secrets = append(rr.Secrets, s)
	}
	sort.Strings(rr.Secrets)
	rr.AllSecrets = all
	if rr.FromFork {
		if visibility(repo) == "public" {
			rr.Reasons = append(rr.Reasons, "triggered by a pull request from a fork: GitHub gave it no repository secrets, only a read-only GITHUB_TOKEN")
			rr.Secrets, rr.AllSecrets = nil, false
		} else {
			rr.Reasons = append(rr.Reasons, "triggered by a pull request from a fork; a private repository can be set to send secrets to fork pull requests, so its secrets are still listed (check the repository's Actions settings)")
		}
	}
	return rr, true
}

// activeSpan is when a run may have executed steps.
type activeSpan struct{ from, to time.Time }

// static is what one workflow file shows, before any log is read.
type static struct {
	jobs       []JobHit
	verdict    incident.Verdict
	secrets    map[string]bool // secrets of the jobs that reached the action
	allSecrets bool
	anyJobHit  bool
	// everySecret / everyAll cover every job in the file, for a run that
	// only its log ties to the compromise.
	everySecret map[string]bool
	everyAll    bool
	err         string
}

// assessWorkflow judges one workflow file at one commit. active, when not
// nil, limits each target to runs active during its window; nil means the
// time is unknown (no run history) and every target applies.
func assessWorkflow(ctx context.Context, res *resolver, in incident.Incident, repo, path, sha string, active *activeSpan) static {
	st := static{secrets: map[string]bool{}}
	data, err := res.get(ctx, repo, path, sha)
	var wf *workflow.File
	if err == nil {
		wf, err = workflow.ParseWorkflow(data)
	}
	if err != nil {
		st.err = "workflow file could not be read at " + short(sha) + ": " + shortErr(err)
		return st
	}
	st.everySecret = map[string]bool{}
	for _, job := range wf.Jobs {
		for _, name := range job.Secrets {
			st.everySecret[name] = true
		}
		if job.AllSecrets {
			st.everyAll = true
		}
		found := res.expand(ctx, repo, sha, job.Uses, path+"@"+short(sha), nil, 0, map[string]bool{})
		jobHit := false
		for _, f := range found {
			for _, t := range in.Targets {
				if active != nil {
					s, e := in.Window(t)
					if active.from.After(e) || active.to.Before(s) {
						continue
					}
				}
				v, why := t.Assess(f.Ref)
				if why == "" {
					continue
				}
				if v == incident.Possible && t.MovedRefs == "tags" && !t.AnyRef && f.Ref.Pin == workflow.PinMutable &&
					res.onlyBranch(ctx, f.Ref.Owner+"/"+f.Ref.Repo, f.Ref.Version) {
					v, why = incident.NotAffected, fmt.Sprintf("%q is a branch, and the advisory says only tags were moved", f.Ref.Version)
				}
				st.jobs = append(st.jobs, JobHit{Job: job.ID, Action: f.Ref.Raw, Verdict: v, Reason: why, Chain: f.Chain})
				if v > st.verdict {
					st.verdict = v
				}
				if v != incident.NotAffected {
					jobHit = true
				}
			}
		}
		if jobHit {
			st.anyJobHit = true
			for _, name := range job.Secrets {
				st.secrets[name] = true
			}
			if job.AllSecrets {
				st.allSecrets = true
			}
		}
	}
	return st
}

// historyFallback handles a repository whose run history does not reach
// back to the window. It reads every workflow on the default branch as it was
// at the end of the window and reports each one that used a compromised
// action with a movable ref as possible: if it ran in the window, it ran the
// malicious code, and nothing left on GitHub can say whether it ran.
func historyFallback(ctx context.Context, src Source, res *resolver, in incident.Incident, repo ghapi.Repo, end time.Time) ([]RunResult, string) {
	if repo.DefaultBranch == "" {
		return nil, "the default branch is unknown, so the workflows from the window could not be read"
	}
	sha, err := src.CommitAt(ctx, repo.FullName, repo.DefaultBranch, end)
	if err != nil {
		return nil, "could not find the " + repo.DefaultBranch + " commit at the end of the window: " + shortErr(err)
	}
	files, err := src.ListDir(ctx, repo.FullName, ".github/workflows", sha)
	if errors.Is(err, ghapi.ErrNotFound) {
		return nil, "the repository had no workflows on " + repo.DefaultBranch + " at the end of the window (commit " + short(sha) + ")"
	}
	if err != nil {
		return nil, "could not list the workflows at " + short(sha) + ": " + shortErr(err)
	}
	var out []RunResult
	cleared := 0
	for _, name := range files {
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		p := ".github/workflows/" + name
		st := assessWorkflow(ctx, res, in, repo.FullName, p, sha, nil)
		if st.verdict != incident.Possible {
			if len(st.jobs) > 0 {
				cleared++
			}
			continue
		}
		rr := RunResult{
			Kind: KindWorkflowFile, Workflow: p, SHA: sha, Branch: repo.DefaultBranch,
			URL:     "https://github.com/" + repo.FullName + "/blob/" + sha + "/" + p,
			Verdict: incident.Possible, Jobs: st.jobs, AllSecrets: st.allSecrets,
			LogStatus: "no run history",
			Reasons: []string{"GitHub no longer lists this repository's runs from the window. This workflow, as it was on " +
				repo.DefaultBranch + " at the end of the window, used the action with a movable ref: if it ran in the window, it ran the compromised code"},
		}
		for name := range st.secrets {
			rr.Secrets = append(rr.Secrets, name)
		}
		sort.Strings(rr.Secrets)
		out = append(out, rr)
	}
	switch {
	case len(out) == 0 && cleared == 0:
		return nil, "none of its workflows on " + repo.DefaultBranch + " at the end of the window (commit " + short(sha) + ") used a compromised action"
	case cleared > 0:
		return out, fmt.Sprintf("%d workflow(s) at commit %s used a compromised action in a way that was not exposed (for example pinned to a commit SHA)", cleared, short(sha))
	}
	return out, ""
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
			all.Skipped = append(all.Skipped, fmt.Sprintf("attempt %d: logs expired", a))
			continue
		}
		if err != nil {
			msg := ghapi.RedactText(shortErr(err))
			errs = append(errs, msg)
			all.Skipped = append(all.Skipped, fmt.Sprintf("attempt %d: %s", a, msg))
			continue
		}
		ev, err := logscan.ScanZip(p, o.Incident.Indicators)
		_ = os.Remove(p)
		if err != nil {
			msg := ghapi.RedactText(err.Error())
			errs = append(errs, msg)
			all.Skipped = append(all.Skipped, fmt.Sprintf("attempt %d: %s", a, msg))
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
			// The runner logs the repository it downloaded ("owner/repo@ref"),
			// never the sub-path, so compare repositories.
			if ref.RepoSlug() != targetRepo(t.Action) {
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

// targetRepo returns the lower-case "owner/repo" of a target action.
func targetRepo(action string) string {
	parts := strings.Split(strings.Trim(strings.ToLower(action), "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "/" + parts[1]
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
		if strings.EqualFold(secret, githubToken) {
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
		if run == 0 {
			return // a workflow-file result has no run to point at
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
			if run.Kind == KindWorkflowFile {
				why = "readable by a workflow that used the compromised action; its runs from the window are no longer listed"
			}
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
