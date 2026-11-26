// Command gh-exposed finds which GitHub Actions runs executed a compromised
// action, proves it from the run logs, and lists the secrets to rotate.
// Installed as a GitHub CLI extension it runs as `gh exposed`.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/hseinmoussa/gh-exposed/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Main(ctx, os.Args[1:], cli.DefaultEnv())
	stop()
	os.Exit(code)
}
