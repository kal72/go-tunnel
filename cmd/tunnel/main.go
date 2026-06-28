package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gotunnel/internal/config"
	"gotunnel/internal/di"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	env, err := config.LoadServerConfig(".env")
	if err != nil {
		return fmt.Errorf("load .env: %w", err)
	}

	log.Printf("[config] Ports: public=%d tunnel=%d",
		env.GatewayPort, env.TunnelPort)
	log.Printf("[config] Domain: %v", env.GatewayDomain)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tunnelApp, cleanup, err := di.BuildTunnelApp(env)
	if err != nil {
		return fmt.Errorf("failed to build server app: %w", err)
	}
	defer cleanup()

	if err := tunnelApp.Run(ctx); err != nil {
		return fmt.Errorf("gateway error: %w", err)
	}
	return nil
}
