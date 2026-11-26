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
		BaseURL:    strings.TrimRight(baseURL, "/"),
		Token:      token,
		HTTP:       &http.Client{Timeout: 5 * time.Minute},
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
			lastErr = err
			if ctx.Err() != nil || attempt >= c.MaxRetries {
				return nil, lastErr
			}
			if err := c.Sleep(ctx, backoff(attempt)); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode < 300 {
			return resp, nil
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		wait, retry := retryAfter(resp, attempt)
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
func retryAfter(resp *http.Response, attempt int) (time.Duration, bool) {
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
	Owner      struct {
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
