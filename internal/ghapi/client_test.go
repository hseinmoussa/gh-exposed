package ghapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTest(t *testing.T, h http.HandlerFunc) (*Client, *[]time.Duration) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := New(srv.URL, "tok")
	var slept []time.Duration
	c.Sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	return c, &slept
}

func TestRateLimitRetry(t *testing.T) {
	var calls atomic.Int32
	c, slept := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing auth header")
		}
		switch calls.Add(1) {
		case 1:
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", fmt.Sprint(time.Now().Add(3*time.Second).Unix()))
			w.WriteHeader(403)
		case 2:
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(403)
		case 3:
			w.WriteHeader(502)
		default:
			w.Write([]byte(`{"full_name":"o/r","private":true}`))
		}
	})
	r, err := c.GetRepo(context.Background(), "o/r")
	if err != nil || r.FullName != "o/r" || !r.Private {
		t.Fatalf("GetRepo = %+v, %v", r, err)
	}
	if len(*slept) != 3 || (*slept)[1] != 2*time.Second {
		t.Errorf("slept = %v", *slept)
	}
}

func TestRateLimitWaitOverCapFails(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7200")
		w.WriteHeader(429)
	})
	_, err := c.GetRepo(context.Background(), "o/r")
	if err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("want rate-limit error, got %v", err)
	}
}

func TestErrorKinds(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/missing":
			w.WriteHeader(404)
		case "/repos/o/secret":
			w.WriteHeader(403)
			w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
		default:
			w.WriteHeader(400)
		}
	})
	if _, err := c.GetRepo(context.Background(), "o/missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("404: %v", err)
	}
	_, err := c.GetRepo(context.Background(), "o/secret")
	if !errors.Is(err, ErrForbidden) || !strings.Contains(err.Error(), "not accessible") {
		t.Errorf("403: %v", err)
	}
	if _, err := c.GetRepo(context.Background(), "o/other"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("400: %v", err)
	}
}

func TestListReposPaginationAndFallback(t *testing.T) {
	var srvURL string
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user":
			w.Write([]byte(`{"login":"me"}`))
		case r.URL.Path == "/orgs/someone/repos":
			w.WriteHeader(404) // a user, not an org
		case r.URL.Path == "/users/someone/repos" && r.URL.Query().Get("page") == "":
			w.Header().Set("Link", `<`+srvURL+`/users/someone/repos?page=2>; rel="next"`)
			w.Write([]byte(`[{"full_name":"someone/a","owner":{"login":"someone"}}]`))
		case r.URL.Path == "/users/someone/repos":
			w.Write([]byte(`[{"full_name":"someone/b","owner":{"login":"Someone"}},{"full_name":"other/c","owner":{"login":"other"}}]`))
		case r.URL.Path == "/user/repos":
			if r.URL.Query().Get("affiliation") != "owner" {
				t.Error("own repos must use affiliation=owner")
			}
			w.Write([]byte(`[{"full_name":"me/private","owner":{"login":"me"}}]`))
		default:
			t.Errorf("unexpected %s", r.URL)
		}
	})
	srvURL = c.BaseURL
	repos, err := c.ListRepos(context.Background(), "someone")
	if err != nil || len(repos) != 2 || repos[1].FullName != "someone/b" {
		t.Fatalf("ListRepos(someone) = %+v, %v", repos, err)
	}
	mine, err := c.ListRepos(context.Background(), "ME")
	if err != nil || len(mine) != 1 || mine[0].FullName != "me/private" {
		t.Fatalf("ListRepos(me) = %+v, %v", mine, err)
	}
}

func TestListRunsSplitsOverCap(t *testing.T) {
	start := time.Date(2025, 3, 14, 0, 0, 0, 0, time.UTC)
	end := start.Add(48 * time.Hour)
	var probes atomic.Int32
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		created := r.URL.Query().Get("created")
		parts := strings.Split(created, "..")
		s, _ := time.Parse(time.RFC3339, parts[0])
		e, _ := time.Parse(time.RFC3339, parts[1])
		if r.URL.Query().Get("per_page") == "1" {
			probes.Add(1)
			total := 1500 // the full window is over the cap
			if e.Sub(s) < 30*time.Hour {
				total = 2
			}
			fmt.Fprintf(w, `{"total_count":%d,"workflow_runs":[]}`, total)
			return
		}
		// Each half returns 2 runs; run 7 appears in both halves (a boundary
		// duplicate) and must be reported once.
		id := s.Unix()
		fmt.Fprintf(w, `{"total_count":2,"workflow_runs":[{"id":%d,"created_at":%q},{"id":7,"created_at":%q}]}`,
			id, s.Format(time.RFC3339), s.Format(time.RFC3339))
	})
	runs, err := c.ListRuns(context.Background(), "o/r", start, end)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 3 {
		t.Errorf("got %d runs, want 3 (two halves, duplicate removed): %+v", len(runs), runs)
	}
	if probes.Load() != 3 {
		t.Errorf("probes = %d, want 3", probes.Load())
	}
}

func TestDownloadRunLogs(t *testing.T) {
	var srvURL string
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/actions/runs/1/attempts/1/logs":
			http.Redirect(w, r, srvURL+"/blob?sig=SECRET", http.StatusFound)
		case "/blob":
			w.Write([]byte("zipbytes"))
		case "/repos/o/r/actions/runs/2/attempts/1/logs":
			w.WriteHeader(410) // expired
		case "/repos/o/r/actions/runs/3/attempts/1/logs":
			w.Write([]byte(strings.Repeat("x", 100)))
		}
	})
	srvURL = c.BaseURL
	p, err := c.DownloadRunLogs(context.Background(), "o/r", 1, 1, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(p)
	if b, _ := os.ReadFile(p); string(b) != "zipbytes" {
		t.Errorf("content = %q", b)
	}
	if _, err := c.DownloadRunLogs(context.Background(), "o/r", 2, 1, 1<<20); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired logs: %v", err)
	}
	if _, err := c.DownloadRunLogs(context.Background(), "o/r", 3, 1, 10); err == nil || !strings.Contains(err.Error(), "max-log-mb") {
		t.Errorf("oversize: %v", err)
	}
}

func TestErrorsNeverIncludeSignedQuery(t *testing.T) {
	if got := redactURL("https://blob/x?sig=SECRET&se=1"); strings.Contains(got, "SECRET") {
		t.Errorf("redactURL kept the query: %s", got)
	}
}

func TestGetFileAndSecrets(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/contents/.github/workflows/my ci.yml":
			if r.URL.Query().Get("ref") != "abc" || r.Header.Get("Accept") != "application/vnd.github.raw" {
				t.Errorf("bad request %s %s", r.URL, r.Header.Get("Accept"))
			}
			w.Write([]byte("jobs: {}"))
		case "/repos/o/r/actions/secrets":
			w.Write([]byte(`{"secrets":[{"name":"A"}]}`))
		case "/repos/o/r/actions/organization-secrets":
			w.Write([]byte(`{"secrets":[{"name":"ORG_B"}]}`))
		default:
			t.Errorf("unexpected %s", r.URL.EscapedPath())
			w.WriteHeader(404)
		}
	})
	b, err := c.GetFile(context.Background(), "o/r", ".github/workflows/my ci.yml", "abc")
	if err != nil || string(b) != "jobs: {}" {
		t.Errorf("GetFile = %q, %v", b, err)
	}
	names, err := c.SecretNames(context.Background(), "o/r")
	if err != nil || strings.Join(names, ",") != "A,ORG_B" {
		t.Errorf("SecretNames = %v, %v", names, err)
	}
}

func TestFromFork(t *testing.T) {
	r := Run{Event: "pull_request", HeadRepository: &struct {
		FullName string `json:"full_name"`
	}{FullName: "attacker/r"}}
	if !r.FromFork("o/r") {
		t.Error("fork PR must be FromFork")
	}
	r.Event = "pull_request_target" // runs with the base repo's secrets
	if r.FromFork("o/r") {
		t.Error("pull_request_target must not be treated as a fork run")
	}
}

func TestSecondaryRateLimitIsRetried(t *testing.T) {
	var calls atomic.Int32
	c, slept := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(403)
			w.Write([]byte(`{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}`))
			return
		}
		w.Write([]byte(`{"full_name":"o/r"}`))
	})
	if _, err := c.GetRepo(context.Background(), "o/r"); err != nil {
		t.Fatal(err)
	}
	if len(*slept) != 1 || (*slept)[0] < time.Minute {
		t.Errorf("slept = %v, want one wait of at least a minute", *slept)
	}
}

func TestRedactErr(t *testing.T) {
	ue := &url.Error{Op: "Get", URL: "https://blob.example/x.zip?sv=1&sig=SECRET", Err: errors.New("connection reset")}
	if got := redactErr(ue).Error(); strings.Contains(got, "SECRET") || !strings.Contains(got, "blob.example/x.zip") {
		t.Errorf("redactErr(url.Error) = %q", got)
	}
	if got := redactErr(errors.New(`read "https://b/x?sig=SECRET": EOF`)).Error(); strings.Contains(got, "SECRET") {
		t.Errorf("redactErr(text) = %q", got)
	}
	if got := RedactText("a https://b/c?sig=SECRET d"); got != "a https://b/c?REDACTED d" {
		t.Errorf("RedactText = %q", got)
	}
}

func TestRedirectedBodyErrorsAreRedacted(t *testing.T) {
	blob := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.Write([]byte("partial"))
		// the handler returns early: the client sees an unexpected EOF
	}))
	defer blob.Close()
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("API call must carry the token")
		}
		http.Redirect(w, r, blob.URL+"/logs.zip?sig=SECRET", http.StatusFound)
	})
	_, err := c.DownloadRunLogs(context.Background(), "o/r", 1, 1, 1<<20)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("want a redacted error, got %v", err)
	}
}
