// Command gh-exposed finds which GitHub Actions runs executed a compromised
// action, proves it from the run logs, and lists the secrets to rotate.
// Installed as a GitHub CLI extension it runs as `gh exposed`.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hseinmoussa/gh-exposed/internal/cli"
)

func main() {
	// SIGTERM matters as much as Ctrl-C: a cancelled CI job sends it, and a
	// cancelled context is what makes the scanner delete the log archive it is
	// holding (which, for a compromised run, contains dumped secrets).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Main(ctx, os.Args[1:], cli.DefaultEnv())
	stop()
	os.Exit(code)
}
