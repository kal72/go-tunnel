package main

import (
	"log"

	"gotunnel/internal/client"
	"gotunnel/internal/config"
)

func main() {
	cfg, err := config.LoadClientConfig("config.yaml")
	if err != nil {
		log.Fatal("load config:", err)
	}
	c := client.NewClient(cfg)
	c.RunForever()
}
