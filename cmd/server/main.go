package main

import (
	"context"
	"gotunnel/internal/tunnel/config"
	"gotunnel/internal/tunnel/edge"
	"gotunnel/internal/tunnel/state"
	"log"
	"os"
	"os/signal"
	"syscall"
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

	db, err := state.InitDB(env)
	if err != nil {
		log.Fatal("init db:", err)
	}
	defer db.Close()

	userRepo := state.NewUserRepository(db)


	e, err := edge.New(env, userRepo)
	if err != nil {
		log.Fatal("init edge:", err)
	}

	if err := e.Run(ctx); err != nil {
		log.Fatal("edge error:", err)
	}
}
