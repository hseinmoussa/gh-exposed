package scan

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/hseinmoussa/gh-exposed/internal/ghapi"
	"github.com/hseinmoussa/gh-exposed/internal/workflow"
)

// UsageRow is one place an action is used today.
type UsageRow struct {
	Repo     string       `json:"repo"`
	Workflow string       `json:"workflow"`
	Job      string       `json:"job"`
	Uses     string       `json:"uses"`
	Pin      workflow.Pin `json:"pin"`
	// Direct is false when the action is reached through a composite action
	// or a reusable workflow; Chain shows the path.
	Direct bool   `json:"direct"`
	Chain  []Link `json:"chain"`
}

// UsageReport answers "where do we use this action right now?" - the first
// question on the day a new compromise is announced, before its exposure
// window is even known.
type UsageReport struct {
	Action string     `json:"action"`
	Repos  int        `json:"repos_scanned"`
	Rows   []UsageRow `json:"rows"`
	Errors []string   `json:"errors,omitempty"`
	Notes  []string   `json:"notes,omitempty"`
}

// Usage scans every workflow on each repository's default branch.
func Usage(ctx context.Context, src Source, action string, repos, owners []string, concurrency int) (*UsageReport, error) {
	targets, targetErrs, err := listTargets(ctx, src, Options{Repos: repos, Owners: owners})
	if err != nil {
		return nil, err
	}
	if concurrency < 1 {
		concurrency = 4
	}
	res := newResolver(src)
	rep := &UsageReport{Action: action, Repos: len(targets)}
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, repo := range targets {
		wg.Add(1)
		go func(repo ghapi.Repo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if e := targetErrs[strings.ToLower(repo.FullName)]; e != nil {
				mu.Lock()
				rep.Errors = append(rep.Errors, repo.FullName+": "+e.Error())
				mu.Unlock()
				return
			}
			rows, err := usageInRepo(ctx, src, res, repo.FullName, action)
			mu.Lock()
			defer mu.Unlock()
			rep.Rows = append(rep.Rows, rows...)
			if err != nil {
				rep.Errors = append(rep.Errors, repo.FullName+": "+err.Error())
			}
		}(repo)
	}
	wg.Wait()
	sort.Slice(rep.Rows, func(i, j int) bool {
		a, b := rep.Rows[i], rep.Rows[j]
		if a.Repo != b.Repo {
			return a.Repo < b.Repo
		}
		if a.Workflow != b.Workflow {
			return a.Workflow < b.Workflow
		}
		return a.Job < b.Job
	})
	sort.Strings(rep.Errors)
	rep.Notes = res.Notes()
	sort.Strings(rep.Notes)
	return rep, ctx.Err()
}

func usageInRepo(ctx context.Context, src Source, res *resolver, repo, action string) ([]UsageRow, error) {
	files, err := src.ListDir(ctx, repo, ".github/workflows", "")
	if errors.Is(err, ghapi.ErrNotFound) {
		return nil, nil // no workflows, or an empty repository
	}
	if err != nil {
		return nil, err
	}
	var rows []UsageRow
	for _, name := range files {
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		p := ".github/workflows/" + name
		data, err := res.get(ctx, repo, p, "")
		if err != nil {
			return rows, err
		}
		wf, err := workflow.ParseWorkflow(data)
		if err != nil {
			res.note("could not parse %s/%s: %v", repo, p, err)
			continue
		}
		for _, job := range wf.Jobs {
			for _, f := range res.expand(ctx, repo, "", job.Uses, p, nil, 0, newExpansion()) {
				if !f.Ref.Matches(action) {
					continue
				}
				rows = append(rows, UsageRow{
					Repo: repo, Workflow: p, Job: job.ID, Uses: f.Ref.Raw,
					Pin: f.Ref.Pin, Direct: len(f.Chain) == 1, Chain: f.Chain,
				})
			}
		}
	}
	return rows, nil
}
