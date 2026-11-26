package workflow

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Use is one `uses:` occurrence with where it was found.
type Use struct {
	Ref  Ref    `json:"ref"`
	Job  string `json:"job"`
	Line int    `json:"line"`
	// Step is the step index inside the job, or -1 for a job-level `uses:`
	// (a reusable workflow call).
	Step int `json:"step"`
}

// Job is what one job exposes.
type Job struct {
	ID   string `json:"id"`
	Uses []Use  `json:"uses"`
	// Secrets are the secret names the job references, sorted. GitHub hands
	// the runner the secrets a job references, so these are the values a
	// memory-dumping payload in that job could read.
	Secrets []string `json:"secrets"`
	// AllSecrets is true when the job reads secrets in a way that names no
	// single secret: `secrets: inherit`, `toJSON(secrets)` or `secrets[...]`.
	// Every secret the repository can see must then be treated as exposed.
	AllSecrets bool `json:"all_secrets"`
}

// File is a parsed workflow (or composite action) file.
type File struct {
	Jobs []Job `json:"jobs"`
	// Errors lists `uses:` values that could not be parsed. They are kept,
	// not fatal: one malformed line must not hide the rest of the file.
	Errors []string `json:"errors,omitempty"`
}

var (
	secretDot     = regexp.MustCompile(`secrets\.([A-Za-z_][A-Za-z0-9_-]*)`)
	secretIndex   = regexp.MustCompile(`secrets\s*\[\s*['"]([A-Za-z_][A-Za-z0-9_-]*)['"]\s*\]`)
	secretDynamic = regexp.MustCompile(`(?i)tojson\(\s*secrets\s*\)|secrets\s*\[\s*[^'"\s]`)
)

// ParseWorkflow parses a workflow file. Workflow-level `env:` that references
// secrets is applied to every job, because GitHub evaluates it for each one.
func ParseWorkflow(data []byte) (*File, error) {
	root, err := decode(data)
	if err != nil {
		return nil, err
	}
	out := &File{}
	var shared []string
	sharedAll := false
	if env := mapGet(root, "env"); env != nil {
		shared, sharedAll = secretRefs(env)
	}
	jobs := mapGet(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return out, nil
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		id, body := jobs.Content[i].Value, jobs.Content[i+1]
		job := Job{ID: id}
		if u := mapGet(body, "uses"); u != nil && u.Kind == yaml.ScalarNode {
			out.addUse(&job, u, -1)
		}
		if steps := mapGet(body, "steps"); steps != nil && steps.Kind == yaml.SequenceNode {
			for si, st := range steps.Content {
				if u := mapGet(st, "uses"); u != nil && u.Kind == yaml.ScalarNode {
					out.addUse(&job, u, si)
				}
			}
		}
		names, all := secretRefs(body)
		if s := mapGet(body, "secrets"); s != nil && s.Kind == yaml.ScalarNode && strings.TrimSpace(s.Value) == "inherit" {
			all = true
		}
		job.Secrets = mergeSorted(names, shared)
		job.AllSecrets = all || sharedAll
		out.Jobs = append(out.Jobs, job)
	}
	return out, nil
}

// ActionFile is a parsed action.yml.
type ActionFile struct {
	Using string `json:"using"`
	// Uses lists the actions a composite action's steps call. It is empty for
	// JavaScript and Docker actions.
	Uses   []Use    `json:"uses"`
	Errors []string `json:"errors,omitempty"`
}

// ParseAction parses an action.yml / action.yaml file.
func ParseAction(data []byte) (*ActionFile, error) {
	root, err := decode(data)
	if err != nil {
		return nil, err
	}
	out := &ActionFile{}
	runs := mapGet(root, "runs")
	if runs == nil {
		return out, nil
	}
	if u := mapGet(runs, "using"); u != nil {
		out.Using = strings.ToLower(strings.TrimSpace(u.Value))
	}
	if out.Using != "composite" {
		return out, nil
	}
	steps := mapGet(runs, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return out, nil
	}
	for si, st := range steps.Content {
		u := mapGet(st, "uses")
		if u == nil || u.Kind != yaml.ScalarNode {
			continue
		}
		ref, perr := ParseRef(u.Value)
		if perr != nil {
			out.Errors = append(out.Errors, fmt.Sprintf("line %d: %v", u.Line, perr))
			continue
		}
		out.Uses = append(out.Uses, Use{Ref: ref, Line: u.Line, Step: si})
	}
	return out, nil
}

func (f *File) addUse(job *Job, n *yaml.Node, step int) {
	ref, err := ParseRef(n.Value)
	if err != nil {
		f.Errors = append(f.Errors, fmt.Sprintf("job %s line %d: %v", job.ID, n.Line, err))
		return
	}
	job.Uses = append(job.Uses, Use{Ref: ref, Job: job.ID, Line: n.Line, Step: step})
}

func decode(data []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if len(doc.Content) == 0 {
		return &yaml.Node{Kind: yaml.MappingNode}, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("parse yaml: top level is not a mapping")
	}
	return root, nil
}

func mapGet(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// secretRefs collects secret names from every scalar under n. It reads
// scalars rather than re-encoding the node so a key that merely contains the
// word "secrets" is not mistaken for an expression.
func secretRefs(n *yaml.Node) (names []string, all bool) {
	seen := map[string]bool{}
	var walk func(*yaml.Node)
	walk = func(x *yaml.Node) {
		if x == nil {
			return
		}
		if x.Kind == yaml.ScalarNode {
			v := x.Value
			if !strings.Contains(v, "secrets") {
				return
			}
			for _, m := range secretDot.FindAllStringSubmatch(v, -1) {
				seen[m[1]] = true
			}
			for _, m := range secretIndex.FindAllStringSubmatch(v, -1) {
				seen[m[1]] = true
			}
			if secretDynamic.MatchString(v) {
				all = true
			}
			return
		}
		for _, c := range x.Content {
			walk(c)
		}
	}
	walk(n)
	for k := range seen {
		names = append(names, k)
	}
	sort.Strings(names)
	return names, all
}

func mergeSorted(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
