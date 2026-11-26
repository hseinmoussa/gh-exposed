// Package incident holds the catalogue of known GitHub Actions compromises
// and the rule that decides whether one `uses:` reference was exposed.
package incident

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hseinmoussa/gh-exposed/internal/workflow"
)

// Target is one compromised action.
type Target struct {
	// Action is "owner/repo" or "owner/repo/path".
	Action string `json:"action"`
	// MaliciousSHAs are the commits the attacker pointed refs at.
	MaliciousSHAs []string `json:"malicious_shas,omitempty"`
	// MaliciousSHAsComplete says the list above is every malicious commit.
	// Only then can a resolved commit that is NOT on the list clear a run.
	MaliciousSHAsComplete bool `json:"malicious_shas_complete,omitempty"`
	// SafeRefs are tags the advisory states were never moved.
	SafeRefs []string `json:"safe_refs,omitempty"`
	// AnyRef marks an action that was affected however it was pinned,
	// because it calls a compromised action internally with a mutable ref.
	AnyRef bool `json:"any_ref,omitempty"`
	// Start and End override the incident window for this target.
	Start *time.Time `json:"start,omitempty"`
	End   *time.Time `json:"end,omitempty"`
}

// Incident is one compromise.
type Incident struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	Advisory   string    `json:"advisory,omitempty"`
	CVE        string    `json:"cve,omitempty"`
	URL        string    `json:"url,omitempty"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
	WindowNote string    `json:"window_note,omitempty"`
	Payload    string    `json:"payload,omitempty"`
	Targets    []Target  `json:"targets"`
	// Indicators are strings whose presence in a run's log proves the
	// malicious code ran (a payload URL, a C2 address).
	Indicators []string `json:"indicators,omitempty"`
}

//go:embed incidents.json
var catalogue []byte

// Builtin returns the built-in incidents, sorted by start time, newest first.
func Builtin() []Incident {
	var out []Incident
	if err := json.Unmarshal(catalogue, &out); err != nil {
		// The file is embedded and covered by a test; failing here is a
		// build defect, not a runtime condition.
		panic(fmt.Sprintf("incidents.json: %v", err))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.After(out[j].Start) })
	return out
}

// Lookup returns the built-in incident with this id.
func Lookup(id string) (Incident, bool) {
	for _, in := range Builtin() {
		if in.ID == id {
			return in, true
		}
	}
	return Incident{}, false
}

// Custom builds an incident from command-line input for a compromise that is
// not in the catalogue yet (the usual case on the day of a new incident).
func Custom(action string, start, end time.Time, shas []string) (Incident, error) {
	action = strings.Trim(strings.TrimSpace(action), "/")
	if strings.Count(action, "/") < 1 {
		return Incident{}, fmt.Errorf("--action must be owner/repo or owner/repo/path, got %q", action)
	}
	if !end.After(start) {
		return Incident{}, fmt.Errorf("--until (%s) must be after --since (%s)", end.Format(time.RFC3339), start.Format(time.RFC3339))
	}
	t := Target{Action: action}
	for _, s := range shas {
		s = strings.ToLower(strings.TrimSpace(s))
		if !workflow.IsFullSHA(s) {
			return Incident{}, fmt.Errorf("--malicious-sha %q is not a full 40-character commit SHA", s)
		}
		t.MaliciousSHAs = append(t.MaliciousSHAs, s)
	}
	return Incident{
		ID:      "custom",
		Title:   "Custom: " + action,
		Start:   start.UTC(),
		End:     end.UTC(),
		Targets: []Target{t},
	}, nil
}

// Validate checks an incident for mistakes that would make results wrong.
func (in Incident) Validate() error {
	if in.ID == "" || len(in.Targets) == 0 {
		return fmt.Errorf("incident %q: needs an id and at least one target", in.ID)
	}
	if !in.End.After(in.Start) {
		return fmt.Errorf("incident %s: end must be after start", in.ID)
	}
	for _, t := range in.Targets {
		if strings.Count(t.Action, "/") < 1 {
			return fmt.Errorf("incident %s: target %q is not owner/repo", in.ID, t.Action)
		}
		for _, s := range t.MaliciousSHAs {
			if !workflow.IsFullSHA(s) || s != strings.ToLower(s) {
				return fmt.Errorf("incident %s: %q is not a lower-case full SHA", in.ID, s)
			}
		}
		if t.MaliciousSHAsComplete && len(t.MaliciousSHAs) == 0 {
			return fmt.Errorf("incident %s: %s marked complete with no SHAs", in.ID, t.Action)
		}
		s, e := in.Window(t)
		if !e.After(s) {
			return fmt.Errorf("incident %s: %s window is empty", in.ID, t.Action)
		}
	}
	return nil
}

// Window returns the exposure window for one target.
func (in Incident) Window(t Target) (time.Time, time.Time) {
	s, e := in.Start, in.End
	if t.Start != nil {
		s = *t.Start
	}
	if t.End != nil {
		e = *t.End
	}
	return s, e
}

// Verdict for one reference or one run, ordered from least to most severe.
type Verdict int

const (
	NotAffected Verdict = iota
	// Possible: the run used the action with a ref that could have been
	// moved, inside the window, and nothing has proved or cleared it.
	Possible
	// Confirmed: the log shows the malicious commit was downloaded, or shows
	// an indicator of compromise, or contains dumped secrets.
	Confirmed
)

func (v Verdict) String() string {
	switch v {
	case Confirmed:
		return "confirmed"
	case Possible:
		return "possible"
	default:
		return "not_affected"
	}
}

// MarshalText makes a Verdict render as its name in JSON.
func (v Verdict) MarshalText() ([]byte, error) { return []byte(v.String()), nil }

// UnmarshalText reads a Verdict back from its name, so JSON reports can be
// consumed by other Go programs (and by this tool's tests).
func (v *Verdict) UnmarshalText(b []byte) error {
	switch string(b) {
	case "confirmed":
		*v = Confirmed
	case "possible":
		*v = Possible
	case "not_affected":
		*v = NotAffected
	default:
		return fmt.Errorf("unknown verdict %q", b)
	}
	return nil
}

// Assess judges one reference against one target, from the workflow file
// alone. It never returns Confirmed: only log evidence can confirm.
// The returned reason is a sentence for the report.
func (t Target) Assess(r workflow.Ref) (Verdict, string) {
	if !r.Matches(t.Action) {
		return NotAffected, ""
	}
	if t.AnyRef {
		return Possible, fmt.Sprintf("%s calls a compromised action internally, so it was affected however it was pinned", t.Action)
	}
	if r.Pin == workflow.PinSHA {
		for _, s := range t.MaliciousSHAs {
			if r.Version == s {
				return Possible, "pinned to the malicious commit " + short(s)
			}
		}
		return NotAffected, "pinned to commit " + short(r.Version) + ", which a tag rewrite cannot move"
	}
	for _, s := range t.SafeRefs {
		if r.Version == s {
			return NotAffected, "the advisory lists " + s + " as never moved"
		}
	}
	return Possible, fmt.Sprintf("pinned to %q, a ref the attacker could move", r.Version)
}

// AssessResolved judges a commit the runner log says it downloaded for this
// target. ok is false when the commit proves nothing either way.
func (t Target) AssessResolved(sha string) (v Verdict, reason string, ok bool) {
	sha = strings.ToLower(sha)
	for _, s := range t.MaliciousSHAs {
		if s == sha {
			return Confirmed, "the run log shows the runner downloaded the malicious commit " + short(s), true
		}
	}
	if t.MaliciousSHAsComplete && !t.AnyRef {
		return NotAffected, "the run log shows the runner downloaded commit " + short(sha) + ", which is not a malicious commit", true
	}
	return Possible, "", false
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
