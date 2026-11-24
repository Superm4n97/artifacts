package main

import (
	"os"

	"github.com/Superm4n97/helm-artifacts/nats-agent/cmd"
)

func main() {
	if err := cmd.NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
