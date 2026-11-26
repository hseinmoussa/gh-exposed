// Package ghapi is a small, read-only GitHub REST client with only the calls
// gh-exposed needs. It has no third-party dependencies on purpose: a tool you
// run during a supply-chain incident should not itself pull in a large
// dependency tree.
package ghapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ErrNotFound is returned for a 404 (and for a 410 on log downloads).
var ErrNotFound = errors.New("not found")

// ErrForbidden is returned for a 403 that is not a rate limit: the token
// lacks a scope or the caller lacks access.
var ErrForbidden = errors.New("forbidden")

// Client talks to the GitHub REST API.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	// Sleep is replaced in tests so rate-limit handling runs instantly.
	Sleep func(context.Context, time.Duration) error
	// MaxRetries bounds retries for rate limits and server errors.
	MaxRetries int
	// MaxWait caps a single rate-limit wait. A longer wait returns an error
	// instead of silently hanging for up to an hour.
	MaxWait time.Duration
	// UserAgent is sent on every request.
	UserAgent string
}

// New returns a client for baseURL ("" means https://api.github.com).
func New(baseURL, token string) *Client {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		// The timeout covers a whole response body, and a large log archive
		// on a slow link can take a while; 30 minutes still bounds a hang.
		HTTP:       &http.Client{Timeout: 30 * time.Minute},
		Sleep:      sleepCtx,
		MaxRetries: 5,
		MaxWait:    15 * time.Minute,
		UserAgent:  "gh-exposed",
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// do sends a GET and retries on rate limits and 5xx. The caller closes the
// body of a successful response.
func (c *Client) do(ctx context.Context, rawURL, accept string) (*http.Response, error) {
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = c.BaseURL + rawURL
	}
	var lastErr error
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		if accept == "" {
			accept = "application/vnd.github+json"
		}
		req.Header.Set("Accept", accept)
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", c.UserAgent)
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = redactErr(err)
			if ctx.Err() != nil || attempt >= c.MaxRetries {
				return nil, lastErr
			}
			if err := c.Sleep(ctx, backoff(attempt)); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode < 300 {
			if resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.RawQuery != "" && resp.Request.URL.Host != req.URL.Host {
				// A redirect to blob storage: the body read that follows can
				// still fail with an error naming the signed URL, so wrap
				// the body to redact it.
				resp.Body = redactingBody{resp.Body}
			}
			return resp, nil
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		wait, retry := retryAfter(resp, body, attempt)
		switch {
		case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
			return nil, fmt.Errorf("%w: GET %s", ErrNotFound, redactURL(rawURL))
		case retry && attempt < c.MaxRetries:
			if wait > c.MaxWait {
				return nil, fmt.Errorf("GitHub rate limit: next request allowed in %s (over the %s cap); re-run later or use a token with a higher limit", wait.Round(time.Second), c.MaxWait)
			}
			if err := c.Sleep(ctx, wait); err != nil {
				return nil, err
			}
			continue
		case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
			return nil, fmt.Errorf("%w: GET %s: %s", ErrForbidden, redactURL(rawURL), apiMessage(body))
		default:
			return nil, fmt.Errorf("GET %s: HTTP %d: %s", redactURL(rawURL), resp.StatusCode, apiMessage(body))
		}
	}
}

// retryAfter decides whether a failed response should be retried and when.
// GitHub signals a primary rate limit with 403/429 and
// X-RateLimit-Remaining: 0 plus X-RateLimit-Reset, and a secondary limit
// with Retry-After.
//
// A secondary rate limit can also arrive as a plain 403 whose message says
// so, with no Retry-After header; GitHub asks clients to wait at least a
// minute before retrying.
func retryAfter(resp *http.Response, body []byte, attempt int) (time.Duration, bool) {
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if s, err := strconv.Atoi(ra); err == nil {
			return time.Duration(s) * time.Second, true
		}
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			if reset, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
				d := time.Until(time.Unix(reset, 0)) + time.Second
				if d < time.Second {
					d = time.Second
				}
				return d, true
			}
			return backoff(attempt), true
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return backoff(attempt), true
		}
		if strings.Contains(strings.ToLower(apiMessage(body)), "secondary rate limit") {
			return time.Minute + backoff(attempt), true
		}
		return 0, false
	}
	if resp.StatusCode >= 500 {
		return backoff(attempt), true
	}
	return 0, false
}

func backoff(attempt int) time.Duration {
	d := time.Second << attempt
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

func apiMessage(body []byte) string {
	var m struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &m) == nil && m.Message != "" {
		return m.Message
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// redactURL drops query strings: log-download redirects carry signed tokens.
func redactURL(u string) string {
	if i := strings.Index(u, "?"); i >= 0 {
		return u[:i]
	}
	return u
}

var queryInText = regexp.MustCompile(`\?[^\s"']*`)

// RedactText removes every query string from free text. Use it on any error
// that may have been produced after a redirect to signed blob storage.
func RedactText(s string) string { return queryInText.ReplaceAllString(s, "?REDACTED") }

// redactErr rewrites a *url.Error so its URL carries no query string, and
// falls back to redacting the text of any other error.
func redactErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		cp := *ue
		cp.URL = redactURL(cp.URL)
		return &cp
	}
	return errors.New(RedactText(err.Error()))
}

// redactingBody redacts errors returned while reading a redirected body.
type redactingBody struct{ io.ReadCloser }

func (b redactingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		err = redactErr(err)
	}
	return n, err
}

func (c *Client) getJSON(ctx context.Context, path string, v any) (http.Header, error) {
	resp, err := c.do(ctx, path, "")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return nil, fmt.Errorf("decode %s: %w", redactURL(path), err)
	}
	return resp.Header, nil
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// paginate calls fn for each page, following Link rel="next".
func (c *Client) paginate(ctx context.Context, path string, fn func(json.RawMessage) error) error {
	next := path
	for next != "" {
		var page json.RawMessage
		h, err := c.getJSON(ctx, next, &page)
		if err != nil {
			return err
		}
		if err := fn(page); err != nil {
			return err
		}
		next = ""
		if m := linkNext.FindStringSubmatch(h.Get("Link")); m != nil {
			next = m[1]
		}
	}
	return nil
}

// Repo is the subset of a repository gh-exposed reports on.
type Repo struct {
	FullName   string `json:"full_name"`
	Private    bool   `json:"private"`
	Visibility string `json:"visibility"`
	Archived   bool   `json:"archived"`
	Fork       bool   `json:"fork"`
	// CreatedAt and DefaultBranch let the scanner tell "no runs because the
	// repository did not exist yet" from "no runs because GitHub no longer
	// keeps them", and read the workflows as they were at a past time.
	CreatedAt     time.Time `json:"created_at"`
	DefaultBranch string    `json:"default_branch"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

// GetRepo reads one repository.
func (c *Client) GetRepo(ctx context.Context, fullName string) (Repo, error) {
	var r Repo
	_, err := c.getJSON(ctx, "/repos/"+fullName, &r)
	return r, err
}

// ListRepos lists every repository owned by an organization or user that the
// token can see. For the token's own user it uses /user/repos, because
// /users/{name}/repos returns public repositories only.
func (c *Client) ListRepos(ctx context.Context, owner string) ([]Repo, error) {
	var me struct {
		Login string `json:"login"`
	}
	if c.Token != "" {
		if _, err := c.getJSON(ctx, "/user", &me); err != nil && !errors.Is(err, ErrForbidden) {
			return nil, err
		}
	}
	var paths []string
	switch {
	case strings.EqualFold(me.Login, owner):
		paths = []string{"/user/repos?affiliation=owner&per_page=100"}
	default:
		paths = []string{
			"/orgs/" + url.PathEscape(owner) + "/repos?type=all&per_page=100",
			"/users/" + url.PathEscape(owner) + "/repos?type=owner&per_page=100",
		}
	}
	var out []Repo
	var err error
	for _, p := range paths {
		out = nil
		err = c.paginate(ctx, p, func(page json.RawMessage) error {
			var rs []Repo
			if err := json.Unmarshal(page, &rs); err != nil {
				return err
			}
			for _, r := range rs {
				if strings.EqualFold(r.Owner.Login, owner) {
					out = append(out, r)
				}
			}
			return nil
		})
		if !errors.Is(err, ErrNotFound) {
			break
		}
	}
	return out, err
}

// GetFile returns a file's raw content at ref ("" means the default branch).
func (c *Client) GetFile(ctx context.Context, fullName, path, ref string) ([]byte, error) {
	p := "/repos/" + fullName + "/contents/" + escapePath(path)
	if ref != "" {
		p += "?ref=" + url.QueryEscape(ref)
	}
	resp, err := c.do(ctx, p, "application/vnd.github.raw")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	// Workflow and action files are small; 5 MiB is far above any real one
	// and stops a hostile repository from making us buffer something huge.
	data, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	return data, err
}

func escapePath(p string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

// ListDir returns the file names in a directory at ref.
func (c *Client) ListDir(ctx context.Context, fullName, path, ref string) ([]string, error) {
	p := "/repos/" + fullName + "/contents/" + escapePath(path)
	if ref != "" {
		p += "?ref=" + url.QueryEscape(ref)
	}
	var entries []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if _, err := c.getJSON(ctx, p, &entries); err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.Type == "file" {
			out = append(out, e.Name)
		}
	}
	return out, nil
}

// Run is a workflow run.
type Run struct {
	ID             int64     `json:"id"`
	Name           string    `json:"name"`
	Path           string    `json:"path"`
	HeadSHA        string    `json:"head_sha"`
	HeadBranch     string    `json:"head_branch"`
	Event          string    `json:"event"`
	Status         string    `json:"status"`
	Conclusion     string    `json:"conclusion"`
	RunAttempt     int       `json:"run_attempt"`
	CreatedAt      time.Time `json:"created_at"`
	RunStartedAt   time.Time `json:"run_started_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	HTMLURL        string    `json:"html_url"`
	HeadRepository *struct {
		FullName string `json:"full_name"`
	} `json:"head_repository"`
}

// FromFork reports whether the run was triggered by a pull request from a
// fork. GitHub does not pass repository secrets to those runs (pull_request
// events), so their exposure is limited to a read-only GITHUB_TOKEN.
func (r Run) FromFork(repoFullName string) bool {
	return r.Event == "pull_request" && r.HeadRepository != nil &&
		!strings.EqualFold(r.HeadRepository.FullName, repoFullName)
}

// runsCap is the most results GitHub returns for a filtered run listing.
const runsCap = 1000

// ListRuns lists workflow runs created in [start, end]. GitHub returns at
// most 1,000 runs for a filtered query, so a window over the cap is split in
// half until every part fits.
func (c *Client) ListRuns(ctx context.Context, fullName string, start, end time.Time) ([]Run, error) {
	seen := map[int64]bool{}
	var out []Run
	var walk func(s, e time.Time) error
	walk = func(s, e time.Time) error {
		q := url.Values{}
		q.Set("created", s.UTC().Format(time.RFC3339)+".."+e.UTC().Format(time.RFC3339))
		q.Set("per_page", "1")
		probe := "/repos/" + fullName + "/actions/runs?" + q.Encode()
		q.Set("per_page", "100")
		base := "/repos/" + fullName + "/actions/runs?" + q.Encode()
		// A one-result probe reads total_count cheaply before deciding
		// whether the window has to be split.
		var first struct {
			TotalCount int `json:"total_count"`
		}
		if _, err := c.getJSON(ctx, probe, &first); err != nil {
			return err
		}
		if first.TotalCount > runsCap && e.Sub(s) > 2*time.Second {
			mid := s.Add(e.Sub(s) / 2).Truncate(time.Second)
			if err := walk(s, mid); err != nil {
				return err
			}
			return walk(mid.Add(time.Second), e)
		}
		if first.TotalCount == 0 {
			return nil
		}
		return c.paginate(ctx, base, func(page json.RawMessage) error {
			var p struct {
				Runs []Run `json:"workflow_runs"`
			}
			if err := json.Unmarshal(page, &p); err != nil {
				return err
			}
			for _, r := range p.Runs {
				if !seen[r.ID] {
					seen[r.ID] = true
					out = append(out, r)
				}
			}
			return nil
		})
	}
	err := walk(start, end)
	return out, err
}

// DownloadRunLogs saves the log archive of one attempt of a run to a temporary
// file and returns its path; the caller removes it. ErrNotFound means the logs
// expired or were deleted.
func (c *Client) DownloadRunLogs(ctx context.Context, fullName string, runID int64, attempt int, maxBytes int64) (string, error) {
	p := fmt.Sprintf("/repos/%s/actions/runs/%d/attempts/%d/logs", fullName, runID, attempt)
	resp, err := c.do(ctx, p, "")
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	f, err := os.CreateTemp("", "gh-exposed-logs-*.zip")
	if err != nil {
		return "", err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxBytes+1))
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err == nil && n > maxBytes {
		err = fmt.Errorf("log archive for run %d is larger than %d bytes; raise --max-log-mb", runID, maxBytes)
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// SecretNames lists the names of the Actions secrets a repository can use:
// its own and the organization secrets shared with it. Both calls need admin
// or secrets-read access; ErrForbidden is returned when the token has
// neither. Environment secrets are not listed.
func (c *Client) SecretNames(ctx context.Context, fullName string) ([]string, error) {
	var out []string
	for _, p := range []string{
		"/repos/" + fullName + "/actions/secrets?per_page=100",
		"/repos/" + fullName + "/actions/organization-secrets?per_page=100",
	} {
		err := c.paginate(ctx, p, func(page json.RawMessage) error {
			var s struct {
				Secrets []struct {
					Name string `json:"name"`
				} `json:"secrets"`
			}
			if err := json.Unmarshal(page, &s); err != nil {
				return err
			}
			for _, x := range s.Secrets {
				out = append(out, x.Name)
			}
			return nil
		})
		if err != nil && !errors.Is(err, ErrNotFound) {
			return out, err
		}
	}
	return out, nil
}

// CountRunsCreatedBefore returns how many runs GitHub still lists that were
// created before t. GitHub deletes old run records (not only their logs), so
// a run listing for an old window can be empty even though runs happened.
// Zero here, for a repository that existed before t, means the listing does
// not reach back to t.
func (c *Client) CountRunsCreatedBefore(ctx context.Context, fullName string, t time.Time) (int, error) {
	q := url.Values{}
	q.Set("created", "<"+t.UTC().Format(time.RFC3339))
	q.Set("per_page", "1")
	var r struct {
		TotalCount int `json:"total_count"`
	}
	_, err := c.getJSON(ctx, "/repos/"+fullName+"/actions/runs?"+q.Encode(), &r)
	return r.TotalCount, err
}

// CommitAt returns the newest commit on branch at or before t, or
// ErrNotFound when the branch has no commit that old.
func (c *Client) CommitAt(ctx context.Context, fullName, branch string, t time.Time) (string, error) {
	q := url.Values{}
	q.Set("sha", branch)
	q.Set("until", t.UTC().Format(time.RFC3339))
	q.Set("per_page", "1")
	var commits []struct {
		SHA string `json:"sha"`
	}
	if _, err := c.getJSON(ctx, "/repos/"+fullName+"/commits?"+q.Encode(), &commits); err != nil {
		return "", err
	}
	if len(commits) == 0 {
		return "", fmt.Errorf("%w: no commit on %s before %s", ErrNotFound, branch, t.Format(time.RFC3339))
	}
	return commits[0].SHA, nil
}

// RefKind reports whether name is a branch and/or a tag in a repository. A
// name can be both; GitHub then has to pick one, so callers must not treat
// such a ref as a branch.
func (c *Client) RefKind(ctx context.Context, fullName, name string) (isBranch, isTag bool, err error) {
	check := func(kind string) (bool, error) {
		var ref struct {
			Ref string `json:"ref"`
		}
		_, err := c.getJSON(ctx, "/repos/"+fullName+"/git/ref/"+kind+"/"+escapePath(name), &ref)
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		// git/ref returns an exact match only, so a 200 means this name.
		return err == nil, err
	}
	if isBranch, err = check("heads"); err != nil {
		return false, false, err
	}
	isTag, err = check("tags")
	return isBranch, isTag, err
}

// RunJobsSpan returns when the earliest job of any attempt of a run started
// and when the latest one finished (a job still running counts as now). Both
// are zero for a run that never started a job. It
// is the reliable answer to "when did this run execute": the run's own
// updated_at moves long after it finished.
func (c *Client) RunJobsSpan(ctx context.Context, fullName string, runID int64) (time.Time, time.Time, error) {
	var first, last time.Time
	seen := 0
	err := c.paginate(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d/jobs?filter=all&per_page=100", fullName, runID), func(page json.RawMessage) error {
		var p struct {
			Jobs []struct {
				StartedAt   time.Time  `json:"started_at"`
				CompletedAt *time.Time `json:"completed_at"`
			} `json:"jobs"`
		}
		if err := json.Unmarshal(page, &p); err != nil {
			return err
		}
		for _, j := range p.Jobs {
			seen++
			end := time.Now().UTC()
			if j.CompletedAt != nil && !j.CompletedAt.IsZero() {
				end = *j.CompletedAt
			}
			if !j.StartedAt.IsZero() && (first.IsZero() || j.StartedAt.Before(first)) {
				first = j.StartedAt
			}
			if end.After(last) {
				last = end
			}
		}
		return nil
	})
	// A run with no jobs at all never executed anything (for example one that
	// failed waiting for approval). It is reported as zero times, no error.
	_ = seen
	return first, last, err
}
