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

	log.Printf("[config] Ports: public=%d tunnel=%d",
		env.GatewayPort, env.TunnelPort)
	log.Printf("[config] Domain: %v", env.GatewayHost)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	gatewaySrv, cleanup, err := di.BuildServerApp(env)
	if err != nil {
		log.Fatalf("failed to build server app: %v", err)
	}
	defer cleanup()

	if err := gatewaySrv.Run(ctx); err != nil {
		log.Fatal("gateway error:", err)
	}
}
