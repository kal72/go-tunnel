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

	log.Printf("[proxy] Ports: public=%d tunnel=%d webui=%d",
		env.GatewayPort, env.TunnelPort, env.WebUIPort)
	log.Printf("[proxy] Domains: Gateway=%s Tunnel=%s WebUI=%s",
		env.GatewayDomain, env.TunnelDomain, env.WebUIDomain)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	proxySrv, cleanup, err := di.BuildProxyApp(env)
	if err != nil {
		return fmt.Errorf("failed to build proxy app: %w", err)
	}
	defer cleanup()

	if err := proxySrv.Run(ctx); err != nil {
		return fmt.Errorf("proxy error: %w", err)
	}
	return nil
}
