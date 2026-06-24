package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"gotunnel/internal/config"
	"gotunnel/internal/di"
)

func main() {
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
		log.Fatalf("failed to build webui app: %v", err)
	}
	defer cleanup()

	port := fmt.Sprintf("%d", env.WebUIPort)
	log.Printf("Tunnel Manager running on http://%s:%s", env.WebUIDomain, port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
