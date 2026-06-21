package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gotunnel/internal/config"
	"gotunnel/internal/di"
)

func main() {
	env, err := config.LoadServerConfig(".env")
	if err != nil {
		log.Fatal("load .env:", err)
	}

	log.Printf("[proxy] Ports: public=%d tunnel=%d webui=%d",
		env.GatewayPort, env.TunnelPort, env.WebUIPort)
	log.Printf("[proxy] Domains: Gateway=%s Tunnel=%s WebUI=%s",
		env.GatewayDomain, env.TunnelDomain, env.WebUIDomain)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	proxySrv, cleanup, err := di.BuildProxyApp(env)
	if err != nil {
		log.Fatalf("failed to build proxy app: %v", err)
	}
	defer cleanup()

	if err := proxySrv.Run(ctx); err != nil {
		log.Fatal("proxy error:", err)
	}
}
