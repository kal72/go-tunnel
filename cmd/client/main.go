package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"gotunnel/internal/tunnel/client"
	"gotunnel/internal/tunnel/config"
)

var (
	version = "dev"
)

func main() {
	// Define command-line flags
	configPath := flag.String("config", "config.yaml", "Path to the configuration file")
	showVersion := flag.Bool("version", false, "Print version information and exit")
	
	// Shorthand aliases
	flag.StringVar(configPath, "c", "config.yaml", "Path to the configuration file (shorthand)")
	flag.BoolVar(showVersion, "v", false, "Print version information and exit (shorthand)")

	// Custom usage message (optional, but recommended for better UX)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of go-tunnel client:\n")
		fmt.Fprintf(os.Stderr, "  client [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("go-tunnel client version: %s\n", version)
		os.Exit(0)
	}

	log.Printf("Starting client using config: %s\n", *configPath)

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config from %s: %v", *configPath, err)
	}
	
	c := client.NewClient(cfg)
	c.RunForever()
}

