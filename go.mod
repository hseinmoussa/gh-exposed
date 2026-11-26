module github.com/hseinmoussa/gh-exposed

go 1.25.0

// The toolchain line is what CI and releases build with (setup-go and
// gh-extension-precompile read it). Keep it on a patched Go: govulncheck
// fails the build otherwise.
toolchain go1.26.11

require gopkg.in/yaml.v3 v3.0.1
