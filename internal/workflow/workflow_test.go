package workflow

import (
	"reflect"
	"testing"
)

func TestParseRef(t *testing.T) {
	sha := "0E58ED8671D6B60D0890C21B07F8835ACE038E67"
	cases := []struct {
		in      string
		kind    Kind
		pin     Pin
		slug    string
		path    string
		version string
		wantErr bool
	}{
		{in: "actions/checkout@v4", kind: KindAction, pin: PinMutable, slug: "actions/checkout", version: "v4"},
		{in: "tj-actions/changed-files@" + sha, kind: KindAction, pin: PinSHA, slug: "tj-actions/changed-files", version: "0e58ed8671d6b60d0890c21b07f8835ace038e67"},
		{in: "github/codeql-action/init@v3", kind: KindAction, pin: PinMutable, slug: "github/codeql-action/init", path: "init", version: "v3"},
		{in: "org/repo/.github/workflows/build.yml@main", kind: KindReusableWorkflow, pin: PinMutable, slug: "org/repo/.github/workflows/build.yml", path: ".github/workflows/build.yml", version: "main"},
		{in: "./.github/actions/setup", kind: KindLocalAction, pin: PinNone, path: ".github/actions/setup"},
		{in: "./.github/workflows/reuse.yaml", kind: KindLocalWorkflow, pin: PinNone, path: ".github/workflows/reuse.yaml"},
		{in: "docker://alpine:3.20", kind: KindDocker, pin: PinNone},
		// A short SHA is not immutable: GitHub resolves it as a ref name.
		{in: "actions/checkout@11bd719", kind: KindAction, pin: PinMutable, slug: "actions/checkout", version: "11bd719"},
		// "@" inside a branch name stays part of the version.
		{in: "  Owner/Repo@release@2  ", kind: KindAction, pin: PinMutable, slug: "owner/repo", version: "release@2"},
		{in: "actions/checkout", wantErr: true},
		{in: "actions/checkout@", wantErr: true},
		{in: "checkout@v4", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, c := range cases {
		r, err := ParseRef(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseRef(%q): want error, got %+v", c.in, r)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRef(%q): %v", c.in, err)
			continue
		}
		if r.Kind != c.kind || r.Pin != c.pin || r.ActionSlug() != c.slug || r.Path != c.path || r.Version != c.version {
			t.Errorf("ParseRef(%q) = kind %s pin %s slug %q path %q version %q; want %s %s %q %q %q",
				c.in, r.Kind, r.Pin, r.ActionSlug(), r.Path, r.Version, c.kind, c.pin, c.slug, c.path, c.version)
		}
	}
}

func TestRefMatches(t *testing.T) {
	r, _ := ParseRef("Reviewdog/Action-Setup/sub@v1")
	for target, want := range map[string]bool{
		"reviewdog/action-setup":       true, // repo-level target matches any path
		"REVIEWDOG/ACTION-SETUP/sub":   true,
		"reviewdog/action-setup/other": false,
		"reviewdog/action-setu":        false,
		"":                             false,
	} {
		if got := r.Matches(target); got != want {
			t.Errorf("Matches(%q) = %v, want %v", target, got, want)
		}
	}
	local, _ := ParseRef("./x")
	if local.Matches("x/y") {
		t.Error("a local action must never match a remote target")
	}
}

const sampleWorkflow = `
name: ci
on: [push, pull_request]
env:
  SHARED: ${{ secrets.SHARED_TOKEN }}
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: changed
        uses: tj-actions/changed-files@v45
        with:
          token: ${{ secrets.GH_PAT }}
      - run: echo "${{ secrets['NPM_TOKEN'] }}"
      - run: echo "key named secrets is not a reference"
  deploy:
    uses: org/infra/.github/workflows/deploy.yml@main
    secrets: inherit
  dump:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ toJSON(secrets) }}'
  matrix:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets[matrix.name] }}
      - uses: not-a-valid-ref
`

func TestParseWorkflow(t *testing.T) {
	f, err := ParseWorkflow([]byte(sampleWorkflow))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Jobs) != 4 {
		t.Fatalf("got %d jobs, want 4", len(f.Jobs))
	}
	lint := f.Jobs[0]
	if lint.ID != "lint" || len(lint.Uses) != 2 {
		t.Fatalf("lint job = %+v", lint)
	}
	if lint.Uses[1].Line != 12 || lint.Uses[1].Step != 1 || !lint.Uses[1].Ref.Matches("tj-actions/changed-files") {
		t.Errorf("changed-files use = %+v", lint.Uses[1])
	}
	if want := []string{"GH_PAT", "NPM_TOKEN", "SHARED_TOKEN"}; !reflect.DeepEqual(lint.Secrets, want) {
		t.Errorf("lint secrets = %v, want %v", lint.Secrets, want)
	}
	if lint.AllSecrets {
		t.Error("lint must not be all-secrets")
	}
	deploy := f.Jobs[1]
	if !deploy.AllSecrets || len(deploy.Uses) != 1 || deploy.Uses[0].Step != -1 || deploy.Uses[0].Ref.Kind != KindReusableWorkflow {
		t.Errorf("deploy job = %+v", deploy)
	}
	if !f.Jobs[2].AllSecrets {
		t.Error("toJSON(secrets) must mark all secrets")
	}
	if !f.Jobs[3].AllSecrets {
		t.Error("secrets[matrix.name] must mark all secrets")
	}
	if len(f.Errors) != 1 {
		t.Errorf("errors = %v, want exactly the invalid ref", f.Errors)
	}
}

func TestParseWorkflowEdgeCases(t *testing.T) {
	for name, src := range map[string]string{
		"empty file":  "",
		"no jobs":     "name: x\non: push\n",
		"jobs scalar": "jobs: nope\n",
	} {
		f, err := ParseWorkflow([]byte(src))
		if err != nil || len(f.Jobs) != 0 {
			t.Errorf("%s: jobs=%v err=%v", name, f, err)
		}
	}
	for name, src := range map[string]string{
		"invalid yaml":   "jobs: [\n",
		"list top level": "- a\n- b\n",
	} {
		if _, err := ParseWorkflow([]byte(src)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestParseAction(t *testing.T) {
	composite := `
name: setup
runs:
  using: Composite
  steps:
    - uses: reviewdog/action-setup@v1
    - run: echo hi
      shell: bash
    - uses: ./inner
`
	a, err := ParseAction([]byte(composite))
	if err != nil {
		t.Fatal(err)
	}
	if a.Using != "composite" || len(a.Uses) != 2 || !a.Uses[0].Ref.Matches("reviewdog/action-setup") || a.Uses[1].Ref.Kind != KindLocalAction {
		t.Errorf("composite = %+v", a)
	}
	js, err := ParseAction([]byte("runs:\n  using: node20\n  main: index.js\n"))
	if err != nil || js.Using != "node20" || len(js.Uses) != 0 {
		t.Errorf("node action = %+v, %v", js, err)
	}
}

func TestAnchorsAliasesAndMergeKeys(t *testing.T) {
	src := `
x-defaults: &defaults
  runs-on: ubuntu-latest
  steps: &steps
    - uses: tj-actions/changed-files@v45
      env: { A: "${{ Secrets.NPM_TOKEN }}" }
x-step: &step
  uses: reviewdog/action-setup@v1
jobs:
  merged:
    <<: *defaults
  aliased:
    runs-on: ubuntu-latest
    steps: *steps
  item:
    runs-on: ubuntu-latest
    steps:
      - *step
      - <<: *step
        with: { x: "${{ SECRETS['AWS_KEY'] }}" }
  override:
    <<: *defaults
    steps:
      - uses: actions/checkout@v4
`
	f, err := ParseWorkflow([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Job{}
	for _, j := range f.Jobs {
		byID[j.ID] = j
	}
	for _, id := range []string{"merged", "aliased"} {
		j := byID[id]
		if len(j.Uses) != 1 || !j.Uses[0].Ref.Matches("tj-actions/changed-files") || len(j.Secrets) != 1 || j.Secrets[0] != "NPM_TOKEN" {
			t.Errorf("%s = %+v", id, j)
		}
	}
	item := byID["item"]
	if len(item.Uses) != 2 || !item.Uses[0].Ref.Matches("reviewdog/action-setup") || !item.Uses[1].Ref.Matches("reviewdog/action-setup") {
		t.Errorf("item uses = %+v", item.Uses)
	}
	if len(item.Secrets) != 1 || item.Secrets[0] != "AWS_KEY" {
		t.Errorf("item secrets = %v", item.Secrets)
	}
	if o := byID["override"]; len(o.Uses) != 1 || !o.Uses[0].Ref.Matches("actions/checkout") {
		t.Errorf("a key written directly must win over a merged one: %+v", o.Uses)
	}
}
