// Package scan answers the incident question: which workflow runs executed a
// compromised action inside its exposure window, what proves it, and which
// secrets those runs could read.
package scan

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/hseinmoussa/gh-exposed/internal/ghapi"
	"github.com/hseinmoussa/gh-exposed/internal/workflow"
)

// Source is the GitHub API surface the scanner uses. *ghapi.Client
// implements it; tests use a fake.
type Source interface {
	GetRepo(ctx context.Context, fullName string) (ghapi.Repo, error)
	ListRepos(ctx context.Context, owner string) ([]ghapi.Repo, error)
	GetFile(ctx context.Context, fullName, path, ref string) ([]byte, error)
	ListDir(ctx context.Context, fullName, path, ref string) ([]string, error)
	ListRuns(ctx context.Context, fullName string, start, end time.Time) ([]ghapi.Run, error)
	DownloadRunLogs(ctx context.Context, fullName string, runID int64, attempt int, maxBytes int64) (string, error)
	SecretNames(ctx context.Context, fullName string) ([]string, error)
	CountRunsCreatedBefore(ctx context.Context, fullName string, t time.Time) (int, error)
	CommitAt(ctx context.Context, fullName, branch string, t time.Time) (string, error)
	RefKind(ctx context.Context, fullName, name string) (isBranch, isTag bool, err error)
	RunJobsSpan(ctx context.Context, fullName string, runID int64) (time.Time, time.Time, error)
}

// Link is one hop in the chain from a workflow to the action that matched.
type Link struct {
	Uses string `json:"uses"`
	File string `json:"file"`
	Line int    `json:"line"`
}

// Found is one action reached from a job, with how it was reached.
type Found struct {
	Ref   workflow.Ref `json:"ref"`
	Chain []Link       `json:"chain"`
}

// maxDepth bounds nested composite actions and reusable workflows. GitHub
// itself allows 4 levels of reusable workflows; 8 leaves room for composites.
const maxDepth = 8

// resolver expands composite actions and reusable workflows. It caches every
// file it fetches, so one action used by many runs is read once.
type resolver struct {
	src   Source
	mu    sync.Mutex
	cache map[string]*fetched
	refs  map[string]refKind
	notes map[string]bool
}

type refKind struct {
	branch, tag bool
	err         error
}

// fetched is one file read. done is closed when data/err are set, so
// concurrent callers for the same file wait for one request instead of each
// sending their own.
type fetched struct {
	done chan struct{}
	data []byte
	err  error
}

func newResolver(src Source) *resolver {
	return &resolver{src: src, cache: map[string]*fetched{}, refs: map[string]refKind{}, notes: map[string]bool{}}
}

func (r *resolver) get(ctx context.Context, repo, p, ref string) ([]byte, error) {
	key := strings.ToLower(repo) + "|" + p + "|" + ref
	r.mu.Lock()
	f, ok := r.cache[key]
	if !ok {
		f = &fetched{done: make(chan struct{})}
		r.cache[key] = f
	}
	r.mu.Unlock()
	if ok {
		select {
		case <-f.done:
			return f.data, f.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.data, f.err = r.src.GetFile(ctx, repo, p, ref)
	// Keep successes and "not found" only. A transient failure kept here
	// would hide a nested compromised action from every later run, so it is
	// returned to the callers already waiting and then forgotten.
	if f.err != nil && !errors.Is(f.err, ghapi.ErrNotFound) {
		r.mu.Lock()
		delete(r.cache, key)
		r.mu.Unlock()
	}
	close(f.done)
	return f.data, f.err
}

// onlyBranch reports whether ref names a branch and NOT a tag in repo,
// caching the answer. Any lookup error counts as "not only a branch", so the
// caller keeps the more cautious verdict.
func (r *resolver) onlyBranch(ctx context.Context, repo, ref string) bool {
	key := strings.ToLower(repo) + "@" + ref
	r.mu.Lock()
	k, ok := r.refs[key]
	r.mu.Unlock()
	if !ok {
		k.branch, k.tag, k.err = r.src.RefKind(ctx, repo, ref)
		r.mu.Lock()
		r.refs[key] = k
		r.mu.Unlock()
		if k.err != nil {
			r.note("could not tell whether %s@%s is a branch or a tag (%v); it was treated as movable", repo, ref, k.err)
		}
	}
	return k.err == nil && k.branch && !k.tag
}

func (r *resolver) note(format string, a ...any) {
	r.mu.Lock()
	r.notes[fmt.Sprintf(format, a...)] = true
	r.mu.Unlock()
}

// Notes returns limitations hit while resolving, for the report.
func (r *resolver) Notes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for n := range r.notes {
		out = append(out, n)
	}
	return out
}

// expansion is the state of one job's expansion: the nested files already
// followed (cycle guard) and the ones that could not be read. A failure is
// recorded so the caller can mark the run as not fully assessed instead of
// silently treating a hidden reference as absent.
type expansion struct {
	visited  map[string]bool
	failures []string
}

func newExpansion() *expansion { return &expansion{visited: map[string]bool{}} }

// expand returns every action a job reaches. repo and sha locate the
// workflow's own repository at the commit that ran; local references
// ("./...") resolve there.
//
// A remote action pinned to a mutable ref is expanded using that ref's
// content TODAY, because GitHub keeps no history of where a tag pointed. If
// an attacker's commit was removed, today's content is the clean one; the
// direct match on the action name still holds, but a nested call the
// attacker added and then removed cannot be seen. Run logs close that gap
// when they still exist (see --deep).
func (r *resolver) expand(ctx context.Context, repo, sha string, uses []workflow.Use, file string, chain []Link, depth int, x *expansion) []Found {
	var out []Found
	for _, u := range uses {
		link := Link{Uses: u.Ref.Raw, File: file, Line: u.Line}
		c := append(append([]Link{}, chain...), link)
		ref := u.Ref
		if ref.Kind == workflow.KindDocker {
			continue
		}
		if ref.Kind == workflow.KindAction || ref.Kind == workflow.KindReusableWorkflow {
			out = append(out, Found{Ref: ref, Chain: c})
		}
		if depth >= maxDepth {
			r.note("nesting deeper than %d levels was not followed (at %s)", maxDepth, ref.Raw)
			continue
		}
		key := ref.ActionSlug() + "@" + ref.Version
		if ref.Owner == "" {
			key = strings.ToLower(repo) + "/" + ref.Path + "@" + sha
		}
		if x.visited[key] {
			continue
		}
		x.visited[key] = true

		switch ref.Kind {
		case workflow.KindAction:
			a, f := r.action(ctx, ref.Owner+"/"+ref.Repo, ref.Path, ref.Version, x)
			if a != nil {
				out = append(out, r.expand(ctx, repo, sha, a.Uses, f, c, depth+1, x)...)
			}
		case workflow.KindLocalAction:
			a, f := r.action(ctx, repo, ref.Path, sha, x)
			if a != nil {
				out = append(out, r.expand(ctx, repo, sha, a.Uses, f, c, depth+1, x)...)
			}
		case workflow.KindReusableWorkflow:
			wf, f := r.workflow(ctx, ref.Owner+"/"+ref.Repo, ref.Path, ref.Version, x)
			if wf != nil {
				// Local references inside a called workflow resolve in the
				// called workflow's repository at the called ref.
				for _, j := range wf.Jobs {
					out = append(out, r.expand(ctx, ref.Owner+"/"+ref.Repo, ref.Version, j.Uses, f, c, depth+1, x)...)
				}
			}
		case workflow.KindLocalWorkflow:
			wf, f := r.workflow(ctx, repo, ref.Path, sha, x)
			if wf != nil {
				for _, j := range wf.Jobs {
					out = append(out, r.expand(ctx, repo, sha, j.Uses, f, c, depth+1, x)...)
				}
			}
		}
	}
	return out
}

// action reads an action.yml. A missing file is a note (the ref may have
// been deleted, which GitHub cannot undo); any other failure is also an
// expansion failure, because the file exists and might hide a nested call.
func (r *resolver) action(ctx context.Context, repo, dir, ref string, x *expansion) (*workflow.ActionFile, string) {
	for _, name := range []string{"action.yml", "action.yaml"} {
		p := path.Join(dir, name)
		data, err := r.get(ctx, repo, p, ref)
		if errors.Is(err, ghapi.ErrNotFound) {
			continue
		}
		label := repo + "/" + p + "@" + ref
		if err != nil {
			r.note("could not read %s: %v", label, err)
			x.failures = append(x.failures, "could not read "+label+": "+shortErr(err))
			return nil, label
		}
		a, err := workflow.ParseAction(data)
		if err != nil {
			r.note("could not parse %s: %v", label, err)
			x.failures = append(x.failures, "could not parse "+label+": "+err.Error())
			return nil, label
		}
		return a, label
	}
	r.note("no action.yml found for %s@%s (the ref may have been deleted)", strings.TrimSuffix(repo+"/"+dir, "/"), ref)
	return nil, ""
}

func (r *resolver) workflow(ctx context.Context, repo, p, ref string, x *expansion) (*workflow.File, string) {
	label := repo + "/" + p + "@" + ref
	data, err := r.get(ctx, repo, p, ref)
	if err != nil {
		r.note("could not read %s: %v", label, err)
		if !errors.Is(err, ghapi.ErrNotFound) {
			x.failures = append(x.failures, "could not read "+label+": "+shortErr(err))
		}
		return nil, label
	}
	wf, err := workflow.ParseWorkflow(data)
	if err != nil {
		r.note("could not parse %s: %v", label, err)
		x.failures = append(x.failures, "could not parse "+label+": "+err.Error())
		return nil, label
	}
	return wf, label
}
