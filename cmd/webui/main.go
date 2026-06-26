package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"gotunnel/internal/config"
	"gotunnel/internal/di"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var configPath string
	flag.StringVar(&configPath, "config", ".env", "Path to the .env configuration file")
	flag.StringVar(&configPath, "c", ".env", "Path to the .env configuration file (shorthand)")
	flag.Parse()

	env, err := config.LoadServerConfig(configPath)
	if err != nil {
		log.Printf("Warning: failed to load config from %s: %v", configPath, err)
	}

	router, cleanup, err := di.BuildWebUIApp(env)
	if err != nil {
		return fmt.Errorf("failed to build webui app: %w", err)
	}
	defer cleanup()

	port := strconv.Itoa(env.WebUIPort)
	log.Printf("Tunnel Manager running on http://%s:%s", env.WebUIDomain, port)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}
