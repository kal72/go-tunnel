package main

import (
	"gotunnel/internal/tunnel/client"
	"gotunnel/internal/tunnel/config"
	"log"
)

func main() {
	cfg, err := config.LoadClientConfig("config.yaml")
	if err != nil {
		log.Fatal("load config:", err)
	}
	c := client.NewClient(cfg)
	c.RunForever()
}
