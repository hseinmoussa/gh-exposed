package incident

import (
	"strings"
	"testing"
	"time"

	"github.com/hseinmoussa/gh-exposed/internal/workflow"
)

func TestBuiltinCatalogueIsValid(t *testing.T) {
	all := Builtin()
	if len(all) < 4 {
		t.Fatalf("want at least 4 built-in incidents, got %d", len(all))
	}
	seen := map[string]bool{}
	for _, in := range all {
		if err := in.Validate(); err != nil {
			t.Error(err)
		}
		if seen[in.ID] {
			t.Errorf("duplicate id %s", in.ID)
		}
		seen[in.ID] = true
		if !strings.HasPrefix(in.URL, "https://github.com/advisories/GHSA-") {
			t.Errorf("%s: every built-in incident must cite its GitHub advisory, got %q", in.ID, in.URL)
		}
	}
	for i := 1; i < len(all); i++ {
		if all[i].Start.After(all[i-1].Start) {
			t.Error("Builtin must be sorted newest first")
		}
	}
	if _, ok := Lookup("tj-actions-changed-files-2025"); !ok {
		t.Error("Lookup must find tj-actions")
	}
	if _, ok := Lookup("nope"); ok {
		t.Error("Lookup must not find an unknown id")
	}
}

func ref(t *testing.T, s string) workflow.Ref {
	t.Helper()
	r, err := workflow.ParseRef(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAssess(t *testing.T) {
	tj, _ := Lookup("tj-actions-changed-files-2025")
	target := tj.Targets[0]
	bad := target.MaliciousSHAs[0]
	cases := []struct {
		uses string
		want Verdict
	}{
		{"tj-actions/changed-files@v45", Possible},
		{"tj-actions/changed-files@main", Possible},
		{"tj-actions/changed-files@" + bad, Possible},
		{"tj-actions/changed-files@" + strings.ToUpper(bad), Possible},
		{"tj-actions/changed-files@" + strings.Repeat("a", 40), NotAffected},
		{"actions/checkout@v4", NotAffected},
		{"tj-actions/changed-files-other@v1", NotAffected},
	}
	for _, c := range cases {
		if got, reason := target.Assess(ref(t, c.uses)); got != c.want {
			t.Errorf("Assess(%s) = %s (%s), want %s", c.uses, got, reason, c.want)
		}
	}

	trivy, _ := Lookup("trivy-action-2026")
	if v, _ := trivy.Targets[0].Assess(ref(t, "aquasecurity/trivy-action@0.35.0")); v != NotAffected {
		t.Error("a safe ref must clear the reference")
	}
	if v, _ := trivy.Targets[0].Assess(ref(t, "aquasecurity/trivy-action@0.34.0")); v != Possible {
		t.Error("an unsafe tag must be possible")
	}

	rd, _ := Lookup("reviewdog-action-setup-2025")
	var shellcheck Target
	for _, tg := range rd.Targets {
		if tg.Action == "reviewdog/action-shellcheck" {
			shellcheck = tg
		}
	}
	if v, _ := shellcheck.Assess(ref(t, "reviewdog/action-shellcheck@"+strings.Repeat("b", 40))); v != Possible {
		t.Error("an any_ref target must be possible even when SHA-pinned")
	}
}

func TestAssessResolved(t *testing.T) {
	tj, _ := Lookup("tj-actions-changed-files-2025")
	target := tj.Targets[0]
	if v, _, ok := target.AssessResolved(strings.ToUpper(target.MaliciousSHAs[0])); !ok || v != Confirmed {
		t.Error("the malicious SHA in the log must confirm")
	}
	if v, _, ok := target.AssessResolved(strings.Repeat("c", 40)); !ok || v != NotAffected {
		t.Error("with a complete SHA list, another SHA must clear")
	}
	trivy, _ := Lookup("trivy-action-2026")
	if _, _, ok := trivy.Targets[0].AssessResolved(strings.Repeat("c", 40)); ok {
		t.Error("with no malicious SHA list, a resolved SHA proves nothing")
	}
}

func TestPerTargetWindow(t *testing.T) {
	trivy, _ := Lookup("trivy-action-2026")
	_, end := trivy.Window(trivy.Targets[1])
	if !end.Equal(time.Date(2026, 3, 19, 21, 44, 0, 0, time.UTC)) {
		t.Errorf("setup-trivy window end = %s", end)
	}
}

func TestCustom(t *testing.T) {
	s := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := s.Add(time.Hour)
	in, err := Custom(" org/act/ ", s, e, []string{strings.Repeat("A", 40)})
	if err != nil || in.Targets[0].Action != "org/act" || in.Targets[0].MaliciousSHAs[0] != strings.Repeat("a", 40) {
		t.Fatalf("Custom = %+v, %v", in, err)
	}
	if err := in.Validate(); err != nil {
		t.Error(err)
	}
	if _, err := Custom("noslash", s, e, nil); err == nil {
		t.Error("want error for action without owner")
	}
	if _, err := Custom("o/r", e, s, nil); err == nil {
		t.Error("want error for reversed window")
	}
	if _, err := Custom("o/r", s, e, []string{"abc123"}); err == nil {
		t.Error("want error for short SHA")
	}
}

func TestVerdictTextRoundTrip(t *testing.T) {
	for _, v := range []Verdict{NotAffected, Possible, Confirmed} {
		b, _ := v.MarshalText()
		var got Verdict
		if err := got.UnmarshalText(b); err != nil || got != v {
			t.Errorf("round trip %s: %v %v", v, got, err)
		}
	}
	var v Verdict
	if err := v.UnmarshalText([]byte("maybe")); err == nil {
		t.Error("want error for unknown verdict")
	}
}
