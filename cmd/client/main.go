package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"gotunnel/internal/client"
)

var (
	version   = "dev"
	ServerURL = "http://localhost:8080"
)

func main() {
	showVersion := flag.Bool("version", false, "Print version information and exit")
	flag.BoolVar(showVersion, "v", false, "Print version information and exit (shorthand)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of go-tunnel client:\n")
		fmt.Fprintf(os.Stderr, "  client login                      Login to the WebUI server\n")
		fmt.Fprintf(os.Stderr, "  client list                       List available remote configurations\n")
		fmt.Fprintf(os.Stderr, "  client run <config_name>          Run a remote configuration\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("go-tunnel client version: %s\n", version)
		os.Exit(0)
	}

	if len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	command := flag.Args()[0]

	switch command {
	case "login":
		loginCmd := flag.NewFlagSet("login", flag.ExitOnError)
		username := loginCmd.String("username", "", "Username")
		password := loginCmd.String("password", "", "Password")
		loginCmd.Parse(flag.Args()[1:])

		if err := client.Login(ServerURL, *username, *password); err != nil {
			log.Fatalf("Login failed: %v", err)
		}

	case "list":
		if err := client.ListConfigs(); err != nil {
			log.Fatalf("Failed to list configs: %v", err)
		}

	case "run":
		if len(flag.Args()) < 2 {
			fmt.Println("Error: config_name is required. Usage: client run <config_name>")
			os.Exit(1)
		}
		configName := flag.Args()[1]

		log.Printf("Fetching configuration: %s\n", configName)
		cfg, err := client.FetchConfig(configName)
		if err != nil {
			log.Fatalf("Failed to fetch config %s: %v", configName, err)
		}

		c := client.NewClient(cfg)
		c.RunForever()

	default:
		fmt.Printf("Unknown command: %s\n", command)
		flag.Usage()
		os.Exit(1)
	}
}
