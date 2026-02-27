package main

import (
	"context"
	"os"

	"github.com/Andrei-Barwood/gcpsec/internal/cli"
)

func main() {
	os.Exit(cli.Run(context.Background(), os.Args[1:]))
}
