package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"gotunnel/internal/client"
)

var (
	version   = "v1.0"
	ServerURL = "http://localhost:8080"
)

func main() {
	showVersion := flag.Bool("version", false, "Print version information and exit")
	flag.BoolVar(showVersion, "v", false, "Print version information and exit (shorthand)")

	flag.Usage = func() {
		banner := `
   ______     ______                     __
  / ____/___ /_  __/_  ______  ____  ___/ /
 / / __/ __ \ / / / / / / __ \/ __ \/ _  / 
/ /_/ / /_/ // / / /_/ / / / / / / /  __/  
\____/\____//_/  \__,_/_/ /_/_/ /_/\___/   `
		fmt.Fprintf(os.Stderr, "\033[1;36m%s\033[0m \033[1;33m%s\033[0m\n\n", banner, version)
		fmt.Fprintf(os.Stderr, "\033[1mGotunnel\033[0m is a client tool for creating secure, encrypted tunnels to your local services.\n\n")

		fmt.Fprintf(os.Stderr, "\033[1mUsage:\033[0m\n")
		fmt.Fprintf(os.Stderr, "  gotunnel [command] [options]\n\n")

		fmt.Fprintf(os.Stderr, "\033[1mAvailable Commands:\033[0m\n")
		fmt.Fprintf(os.Stderr, "  \033[32mlogin\033[0m                      Login to the WebUI server\n")
		fmt.Fprintf(os.Stderr, "  \033[32mlist\033[0m                       List available remote configurations\n")
		fmt.Fprintf(os.Stderr, "  \033[32mrun\033[0m <config_name>          Run a remote configuration\n")
		fmt.Fprintf(os.Stderr, "  \033[32mupdate\033[0m                     Update gotunnel to the latest version\n")
		fmt.Fprintf(os.Stderr, "  \033[32mlogout\033[0m                     Logout and clear credentials\n")
		fmt.Fprintf(os.Stderr, "  \033[32muninstall\033[0m                  Uninstall gotunnel and clear local data\n\n")

		fmt.Fprintf(os.Stderr, "\033[1mOptions:\033[0m\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n")
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("version: %s\n", version)
		os.Exit(0)
	}

	if len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	command := flag.Args()[0]

	if command != "update" && command != "uninstall" {
		client.CheckForNewVersion(ServerURL, version)
	}

	switch command {
	case "login":
		loginCmd := flag.NewFlagSet("login", flag.ExitOnError)
		username := loginCmd.String("username", "", "Username")
		password := loginCmd.String("password", "", "Password")
		_ = loginCmd.Parse(flag.Args()[1:])

		if err := client.Login(ServerURL, *username, *password); err != nil {
			log.Fatalf("Login failed: %v", err)
		}

	case "logout":
		if err := client.Logout(); err != nil {
			log.Fatalf("Logout error: %v", err)
		}

	case "update":
		if err := client.UpdateClient(ServerURL, version); err != nil {
			log.Fatalf("Update error: %v", err)
		}

	case "uninstall":
		if err := client.UninstallClient(); err != nil {
			log.Fatalf("Uninstall error: %v", err)
		}

	case "list":
		if err := client.ListConfigs(ServerURL); err != nil {
			log.Fatalf("Failed to list configs: %v", err)
		}

	case "run":
		if len(flag.Args()) < 2 {
			fmt.Println("Error: config_name is required. Usage: gotunnel run <config_name>")
			os.Exit(1)
		}
		configName := flag.Args()[1]

		log.Printf("Fetching configuration: %s\n", configName)
		cfg, err := client.FetchConfig(ServerURL, configName)
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
