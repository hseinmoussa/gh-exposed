// Package workflow parses GitHub Actions workflow and action files into the
// facts gh-exposed needs: which actions a job uses (and how they are pinned)
// and which secrets the job can read.
package workflow

import (
	"fmt"
	"regexp"
	"strings"
)

// Kind says what a `uses:` value points at.
type Kind string

const (
	KindAction           Kind = "action"            // owner/repo[/path]@ref
	KindReusableWorkflow Kind = "reusable_workflow" // owner/repo/.github/workflows/x.yml@ref
	KindLocalAction      Kind = "local_action"      // ./path
	KindLocalWorkflow    Kind = "local_workflow"    // ./.github/workflows/x.yml
	KindDocker           Kind = "docker"            // docker://image
)

// Pin says how a remote reference is pinned.
type Pin string

const (
	// PinSHA is a full 40-character commit SHA: immutable, cannot be moved by
	// a tag rewrite.
	PinSHA Pin = "sha"
	// PinMutable is anything else (a tag or a branch). GitHub resolves it at
	// run time, which is exactly what a tag-rewrite attack exploits. We do not
	// try to tell tags from branches: both can be moved by whoever controls
	// the repository.
	PinMutable Pin = "mutable"
	// PinNone is for local and docker references, which have no git ref.
	PinNone Pin = "none"
)

// Ref is one parsed `uses:` value.
type Ref struct {
	Raw   string `json:"raw"`
	Kind  Kind   `json:"kind"`
	Owner string `json:"owner,omitempty"`
	Repo  string `json:"repo,omitempty"`
	// Path is the sub-directory (for an action) or the workflow file path
	// (for a reusable workflow) inside the repository. Empty for an action at
	// the repository root.
	Path string `json:"path,omitempty"`
	// Version is the part after "@".
	Version string `json:"version,omitempty"`
	Pin     Pin    `json:"pin"`
}

var fullSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// IsFullSHA reports whether s is a full 40-character hexadecimal commit SHA.
func IsFullSHA(s string) bool { return fullSHA.MatchString(s) }

// ParseRef parses a `uses:` value. It returns an error for values that GitHub
// itself would reject (a remote reference without "@ref", or without an
// owner and repository).
func ParseRef(raw string) (Ref, error) {
	s := strings.TrimSpace(raw)
	r := Ref{Raw: s, Pin: PinNone}
	switch {
	case s == "":
		return r, fmt.Errorf("empty uses value")
	case strings.HasPrefix(s, "docker://"):
		r.Kind = KindDocker
		return r, nil
	case strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../"):
		r.Path = strings.TrimPrefix(s, "./")
		if isWorkflowPath(r.Path) {
			r.Kind = KindLocalWorkflow
		} else {
			r.Kind = KindLocalAction
		}
		return r, nil
	}

	// Owner and repository names cannot contain "@", so the first "@" ends
	// the name and everything after it is the ref (which may contain "@").
	at := strings.Index(s, "@")
	if at <= 0 || at == len(s)-1 {
		return r, fmt.Errorf("remote uses %q has no @ref", s)
	}
	r.Version = s[at+1:]
	parts := strings.Split(s[:at], "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return r, fmt.Errorf("remote uses %q has no owner/repo", s)
	}
	r.Owner, r.Repo = parts[0], parts[1]
	r.Path = strings.Join(parts[2:], "/")
	if isWorkflowPath(r.Path) {
		r.Kind = KindReusableWorkflow
	} else {
		r.Kind = KindAction
	}
	if IsFullSHA(r.Version) {
		r.Pin = PinSHA
		r.Version = strings.ToLower(r.Version)
	} else {
		r.Pin = PinMutable
	}
	return r, nil
}

func isWorkflowPath(p string) bool {
	return strings.HasPrefix(p, ".github/workflows/") &&
		(strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml"))
}

// RepoSlug returns "owner/repo" in lower case, or "" for local and docker refs.
func (r Ref) RepoSlug() string {
	if r.Owner == "" {
		return ""
	}
	return strings.ToLower(r.Owner + "/" + r.Repo)
}

// ActionSlug returns "owner/repo" or "owner/repo/path" in lower case.
func (r Ref) ActionSlug() string {
	if r.Owner == "" {
		return ""
	}
	if r.Path == "" {
		return r.RepoSlug()
	}
	return r.RepoSlug() + "/" + strings.ToLower(strings.Trim(r.Path, "/"))
}

// Matches reports whether this reference uses the action named by target,
// written as "owner/repo" (any path inside that repository matches) or
// "owner/repo/path" (only that path matches). Matching ignores case, as
// GitHub does for owner and repository names.
func (r Ref) Matches(target string) bool {
	t := strings.ToLower(strings.Trim(strings.TrimSpace(target), "/"))
	if r.Owner == "" || t == "" {
		return false
	}
	if strings.Count(t, "/") == 1 {
		return r.RepoSlug() == t
	}
	return r.ActionSlug() == t
}
