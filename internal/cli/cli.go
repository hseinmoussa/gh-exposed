// Package cli is the gh-exposed command line. It lives outside package main
// so every command can be tested.
package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"time"

	"github.com/hseinmoussa/gh-exposed/internal/ghapi"
	"github.com/hseinmoussa/gh-exposed/internal/incident"
	"github.com/hseinmoussa/gh-exposed/internal/report"
	"github.com/hseinmoussa/gh-exposed/internal/scan"
)

// Exit codes. A CI job can fail on ExitPossible or only on ExitConfirmed.
const (
	ExitOK        = 0
	ExitError     = 1
	ExitPossible  = 2
	ExitConfirmed = 3
	ExitUsage     = 64
)

// Version can be set at build time with
// -ldflags "-X github.com/hseinmoussa/gh-exposed/internal/cli.Version=v1.2.3".
// When it is not, version() falls back to the module version (set by
// `go install ...@vX`) and then to the VCS revision the binary was built from
// (set by `gh extension install`, which builds from a tag).
var Version = ""

func version() string {
	if Version != "" {
		return Version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 12 {
			return "dev-" + s.Value[:12]
		}
	}
	return "dev"
}

// Env is everything the CLI touches outside itself, so tests can swap it.
type Env struct {
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	// NewSource builds the GitHub client; tests return a fake.
	NewSource func(apiURL, token string) scan.Source
	// GHToken runs `gh auth token`.
	GHToken func() (string, error)
	Now     func() time.Time
}

// DefaultEnv is the real environment.
func DefaultEnv() Env {
	return Env{
		Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv,
		NewSource: func(apiURL, token string) scan.Source { return ghapi.New(apiURL, token) },
		GHToken: func() (string, error) {
			out, err := exec.Command("gh", "auth", "token").Output()
			return strings.TrimSpace(string(out)), err
		},
		Now: time.Now,
	}
}

const usage = `gh-exposed: find which GitHub Actions runs executed a compromised action,
prove it from the logs, and list the secrets to rotate.

Usage:
  gh exposed scan --incident ID (--owner ORG | --repo OWNER/REPO)... [flags]
  gh exposed scan --action OWNER/REPO --since TIME --until TIME (--owner|--repo)... [flags]
  gh exposed usage --action OWNER/REPO (--owner ORG | --repo OWNER/REPO)... [flags]
  gh exposed incidents [--format text|markdown|json]
  gh exposed version

Run "gh exposed <command> -h" for the flags of a command.

Exit codes: 0 nothing exposed, 2 possible exposure, 3 confirmed exposure,
1 error or incomplete scan, 64 bad usage.

The token comes from GH_TOKEN, then GITHUB_TOKEN, then "gh auth token".
It needs read access to the repositories (and to their Actions secrets if
you want secret names listed for jobs that read every secret).
`

// Main runs the CLI and returns the exit code.
func Main(ctx context.Context, args []string, env Env) int {
	if len(args) == 0 {
		fmt.Fprint(env.Stderr, usage)
		return ExitUsage
	}
	switch args[0] {
	case "scan":
		return cmdScan(ctx, args[1:], env)
	case "usage":
		return cmdUsage(ctx, args[1:], env)
	case "incidents":
		return cmdIncidents(args[1:], env)
	case "version", "--version", "-v":
		fmt.Fprintln(env.Stdout, "gh-exposed", version())
		return ExitOK
	case "help", "-h", "--help":
		fmt.Fprint(env.Stdout, usage)
		return ExitOK
	}
	fmt.Fprintf(env.Stderr, "unknown command %q\n\n%s", args[0], usage)
	return ExitUsage
}

type multi []string

func (m *multi) String() string { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*m = append(*m, s)
		}
	}
	return nil
}

type common struct {
	repos, owners multi
	format        string
	out           string
	apiURL        string
	concurrency   int
}

func (c *common) register(fs *flag.FlagSet) {
	fs.Var(&c.repos, "repo", "repository OWNER/REPO to scan (repeatable, or comma-separated)")
	fs.Var(&c.owners, "owner", "organization or user: scan every repository the token can see (repeatable)")
	fs.StringVar(&c.format, "format", "text", "output format: text, markdown or json")
	fs.StringVar(&c.out, "out", "", "write the report to this file instead of stdout")
	fs.StringVar(&c.apiURL, "api-url", "", "GitHub API URL, for GitHub Enterprise Server (default https://api.github.com)")
	fs.IntVar(&c.concurrency, "concurrency", 4, "repositories scanned at once")
}

func (c *common) validate() error {
	if len(c.repos) == 0 && len(c.owners) == 0 {
		return errors.New("pass --repo OWNER/REPO or --owner ORG")
	}
	for _, r := range c.repos {
		if strings.Count(r, "/") != 1 || strings.HasPrefix(r, "/") || strings.HasSuffix(r, "/") {
			return fmt.Errorf("--repo %q must be OWNER/REPO", r)
		}
	}
	if c.concurrency < 1 || c.concurrency > 32 {
		return errors.New("--concurrency must be between 1 and 32")
	}
	return nil
}

func newFlagSet(name string, env Env) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	return fs
}

func token(env Env) (string, error) {
	for _, k := range []string{"GH_TOKEN", "GITHUB_TOKEN"} {
		if v := strings.TrimSpace(env.Getenv(k)); v != "" {
			return v, nil
		}
	}
	t, err := env.GHToken()
	if err != nil || t == "" {
		return "", errors.New("no GitHub token: set GH_TOKEN, or log in with `gh auth login`")
	}
	return t, nil
}

// output writes the rendered report to stdout or --out. Rendering into a
// buffer first means a failed render never leaves a half-written file.
func output(env Env, path string, render func(io.Writer) error) error {
	var buf bytes.Buffer
	if err := render(&buf); err != nil {
		return err
	}
	if path == "" {
		_, err := env.Stdout.Write(buf.Bytes())
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

// parseTime accepts RFC 3339 or a date (YYYY-MM-DD, UTC). A date passed as
// --until means the END of that day, so "--since 2025-03-14 --until
// 2025-03-15" covers both whole days, as an advisory written in dates means.
func parseTime(s string, endOfDay bool) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not a date (YYYY-MM-DD) or RFC 3339 time", s)
	}
	if endOfDay {
		t = t.Add(24 * time.Hour)
	}
	return t, nil
}

func cmdScan(ctx context.Context, args []string, env Env) int {
	fs := newFlagSet("scan", env)
	var c common
	c.register(fs)
	id := fs.String("incident", "", "built-in incident ID (see `gh exposed incidents`)")
	action := fs.String("action", "", "compromised action OWNER/REPO[/PATH], for an incident not in the catalogue")
	since := fs.String("since", "", "start of the exposure window (YYYY-MM-DD or RFC 3339, UTC)")
	until := fs.String("until", "", "end of the exposure window (a date means the end of that day)")
	var shas multi
	fs.Var(&shas, "malicious-sha", "a commit the attacker pointed refs at (repeatable); log evidence of it confirms a run")
	noLogs := fs.Bool("no-logs", false, "do not download run logs (faster, but nothing can be confirmed or cleared)")
	deep := fs.Bool("deep", false, "scan the logs of EVERY run in the window, not only runs the workflow files flag")
	maxLog := fs.Int("max-log-mb", 500, "largest run log archive to download, in MiB")
	failOn := fs.String("fail-on", "possible", "exit non-zero on: possible, confirmed, or never")
	fs.Usage = func() { fmt.Fprintln(env.Stderr, "Usage: gh exposed scan [flags]"); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(env.Stderr, "unexpected argument %q\n", fs.Arg(0))
		return ExitUsage
	}
	if err := c.validate(); err != nil {
		fmt.Fprintln(env.Stderr, err)
		return ExitUsage
	}
	format, err := report.ParseFormat(c.format)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return ExitUsage
	}
	if *failOn != "possible" && *failOn != "confirmed" && *failOn != "never" {
		fmt.Fprintln(env.Stderr, "--fail-on must be possible, confirmed or never")
		return ExitUsage
	}
	if *maxLog < 1 {
		fmt.Fprintln(env.Stderr, "--max-log-mb must be at least 1")
		return ExitUsage
	}
	if *noLogs && *deep {
		fmt.Fprintln(env.Stderr, "--deep reads logs; it cannot be combined with --no-logs")
		return ExitUsage
	}

	var in incident.Incident
	switch {
	case *id != "" && *action != "":
		fmt.Fprintln(env.Stderr, "pass either --incident or --action, not both")
		return ExitUsage
	case *id != "":
		var ok bool
		if in, ok = incident.Lookup(*id); !ok {
			fmt.Fprintf(env.Stderr, "unknown incident %q; run `gh exposed incidents` for the list\n", *id)
			return ExitUsage
		}
	case *action != "":
		if *since == "" || *until == "" {
			fmt.Fprintln(env.Stderr, "--action needs --since and --until")
			return ExitUsage
		}
		s, err1 := parseTime(*since, false)
		u, err2 := parseTime(*until, true)
		if err := errors.Join(err1, err2); err != nil {
			fmt.Fprintln(env.Stderr, err)
			return ExitUsage
		}
		if u.After(env.Now()) {
			u = env.Now().UTC() // the exposure may be ongoing
		}
		if in, err = incident.Custom(*action, s, u, shas); err != nil {
			fmt.Fprintln(env.Stderr, err)
			return ExitUsage
		}
	default:
		fmt.Fprintln(env.Stderr, "pass --incident ID or --action OWNER/REPO with --since and --until")
		return ExitUsage
	}

	tok, err := token(env)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return ExitError
	}
	rep, err := scan.Run(ctx, env.NewSource(c.apiURL, tok), scan.Options{
		Incident: in, Repos: c.repos, Owners: c.owners,
		Logs: !*noLogs, Deep: *deep, MaxLogBytes: int64(*maxLog) << 20, Concurrency: c.concurrency,
		Progress: func(s string) { fmt.Fprintln(env.Stderr, s) },
	})
	if err != nil {
		fmt.Fprintln(env.Stderr, "scan failed:", err)
		return ExitError
	}
	if err := output(env, c.out, func(w io.Writer) error { return report.Scan(w, format, rep) }); err != nil {
		fmt.Fprintln(env.Stderr, err)
		return ExitError
	}
	if c.out != "" {
		fmt.Fprintln(env.Stderr, "report written to", c.out)
	}
	switch worst := rep.Worst(); {
	case *failOn == "never":
		return ExitOK
	case worst == incident.Confirmed:
		return ExitConfirmed
	case worst == incident.Possible && *failOn == "possible":
		return ExitPossible
	case rep.Incomplete():
		// Nothing was found, but part of the scan failed: that is not a
		// clean result, and a CI gate must not read it as one.
		fmt.Fprintln(env.Stderr, "the scan is incomplete (see the report); exiting with an error")
		return ExitError
	}
	return ExitOK
}

func cmdUsage(ctx context.Context, args []string, env Env) int {
	fs := newFlagSet("usage", env)
	var c common
	c.register(fs)
	action := fs.String("action", "", "action OWNER/REPO[/PATH] to look for")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Usage: gh exposed usage --action OWNER/REPO [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if err := c.validate(); err != nil {
		fmt.Fprintln(env.Stderr, err)
		return ExitUsage
	}
	if strings.Count(strings.Trim(*action, "/"), "/") < 1 {
		fmt.Fprintln(env.Stderr, "--action OWNER/REPO is required")
		return ExitUsage
	}
	format, err := report.ParseFormat(c.format)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return ExitUsage
	}
	tok, err := token(env)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return ExitError
	}
	rep, err := scan.Usage(ctx, env.NewSource(c.apiURL, tok), *action, c.repos, c.owners, c.concurrency)
	if err != nil {
		fmt.Fprintln(env.Stderr, "usage scan failed:", err)
		return ExitError
	}
	if err := output(env, c.out, func(w io.Writer) error { return report.Usage(w, format, rep) }); err != nil {
		fmt.Fprintln(env.Stderr, err)
		return ExitError
	}
	if len(rep.Errors) > 0 {
		return ExitError
	}
	return ExitOK
}

func cmdIncidents(args []string, env Env) int {
	fs := newFlagSet("incidents", env)
	f := fs.String("format", "text", "output format: text, markdown or json")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	format, err := report.ParseFormat(*f)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return ExitUsage
	}
	if err := report.Incidents(env.Stdout, format, incident.Builtin()); err != nil {
		fmt.Fprintln(env.Stderr, err)
		return ExitError
	}
	return ExitOK
}
