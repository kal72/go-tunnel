package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

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
		fmt.Fprintf(os.Stderr, "  \033[32mrun\033[0m [-token gtk_xxx] <config_name>  Run a remote configuration\n")
		fmt.Fprintf(os.Stderr, "  \033[32mforward\033[0m <hostname> <port>   Forward a local port to a TCP tunnel\n")
		fmt.Fprintf(os.Stderr, "  \033[32mupdate\033[0m                     Update gotunnel to the latest version\n")
		fmt.Fprintf(os.Stderr, "  \033[32mlogout\033[0m                     Logout and clear credentials\n")
		fmt.Fprintf(os.Stderr, "  \033[32muninstall\033[0m                  Uninstall gotunnel and clear local data\n\n")

		fmt.Fprintf(os.Stderr, "\033[1mForward Examples:\033[0m\n")
		fmt.Fprintf(os.Stderr, "  RDP (Windows Remote Desktop):\n")
		fmt.Fprintf(os.Stderr, "    gotunnel forward rdp.domain.com 3389\n")
		fmt.Fprintf(os.Stderr, "    → then connect RDP client to localhost:3389\n\n")
		fmt.Fprintf(os.Stderr, "  Database access (MySQL, PostgreSQL, Redis, MongoDB, MSSQL):\n")
		fmt.Fprintf(os.Stderr, "    gotunnel forward db.domain.com 5432\n")
		fmt.Fprintf(os.Stderr, "    → then open DBeaver/TablePlus to localhost:5432\n\n")
		fmt.Fprintf(os.Stderr, "  VNC screen sharing:\n")
		fmt.Fprintf(os.Stderr, "    gotunnel forward vnc.domain.com 5900\n\n")
		fmt.Fprintf(os.Stderr, "  Custom local port (avoid conflicts):\n")
		fmt.Fprintf(os.Stderr, "    gotunnel forward --local-port 13389 rdp.domain.com 3389\n\n")
		fmt.Fprintf(os.Stderr, "  NOTE: Tunnel must be configured with mode=tcp on the agent side.\n")
		fmt.Fprintf(os.Stderr, "        All traffic flows over port 443 (HTTPS) — safe from port blocking.\n\n")

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
		client.CheckForNewVersion(ServerURL, version)
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
		runCmd := flag.NewFlagSet("run", flag.ExitOnError)
		tokenFlag := runCmd.String("token", "", "API key for authentication (gtk_...)")
		runCmd.StringVar(tokenFlag, "t", "", "API key for authentication (shorthand)")
		_ = runCmd.Parse(flag.Args()[1:])

		if runCmd.NArg() < 1 {
			fmt.Println("Error: config_name is required. Usage: gotunnel run [-token gtk_xxx] <config_name>")
			os.Exit(1)
		}
		configName := runCmd.Arg(0)

		// Check for token: flag > env > stored
		token := *tokenFlag
		if token == "" {
			token = os.Getenv("GOTUNNEL_TOKEN")
		}

		// Validate token format if provided
		if token != "" {
			if !strings.HasPrefix(token, "gtk_") {
				fmt.Fprintln(os.Stderr, "Error: token must start with 'gtk_' prefix")
				os.Exit(1)
			}
		}

		log.Printf("Fetching configuration: %s\n", configName)
		cfg, err := client.FetchConfig(ServerURL, configName)
		if err != nil {
			log.Fatalf("Failed to fetch config %s: %v", configName, err)
		}

		// Override auth token if direct token provided
		if token != "" {
			cfg.AuthToken = token
		}

		// Check that we have some form of authentication
		if cfg.AuthToken == "" {
			fmt.Fprintln(os.Stderr, "Error: authentication required. Use --token flag, GOTUNNEL_TOKEN env, or run 'gotunnel login'")
			os.Exit(1)
		}

		c := client.NewClient(cfg)
		c.RunForever()

	case "forward":
		forwardCmd := flag.NewFlagSet("forward", flag.ExitOnError)
		localPort := forwardCmd.Int("local-port", 0, "Local port to listen on (default: same as target port)")
		insecure := forwardCmd.Bool("insecure", false, "Skip TLS certificate verification (development only)")
		forwardCmd.Usage = func() {
			fmt.Fprintf(os.Stderr, "Usage: gotunnel forward [options] <hostname> <port>\n\n")
			fmt.Fprintf(os.Stderr, "Forward a local TCP port through go-tunnel to a remote service.\n")
			fmt.Fprintf(os.Stderr, "Works for any TCP protocol: RDP, VNC, MySQL, PostgreSQL, Redis, MSSQL, MongoDB, etc.\n")
			fmt.Fprintf(os.Stderr, "All traffic is encrypted and flows through port 443 — no port 3389/5432/etc needed.\n\n")
			fmt.Fprintf(os.Stderr, "Options:\n")
			forwardCmd.PrintDefaults()
			fmt.Fprintf(os.Stderr, "\nExamples:\n")
			fmt.Fprintf(os.Stderr, "  gotunnel forward rdp.domain.com 3389          # RDP to localhost:3389\n")
			fmt.Fprintf(os.Stderr, "  gotunnel forward db.domain.com 5432           # PostgreSQL to localhost:5432\n")
			fmt.Fprintf(os.Stderr, "  gotunnel forward db.domain.com 3306           # MySQL to localhost:3306\n")
			fmt.Fprintf(os.Stderr, "  gotunnel forward redis.domain.com 6379        # Redis to localhost:6379\n")
			fmt.Fprintf(os.Stderr, "  gotunnel forward vnc.domain.com 5900          # VNC to localhost:5900\n")
			fmt.Fprintf(os.Stderr, "  gotunnel forward --local-port 13389 rdp.domain.com 3389  # custom local port\n")
		}
		_ = forwardCmd.Parse(flag.Args()[1:])

		if forwardCmd.NArg() < 2 {
			forwardCmd.Usage()
			os.Exit(1)
		}

		hostname := forwardCmd.Arg(0)
		targetPortStr := forwardCmd.Arg(1)
		targetPort, err := strconv.Atoi(targetPortStr)
		if err != nil || targetPort < 1 || targetPort > 65535 {
			fmt.Fprintf(os.Stderr, "Error: invalid port %q — must be a number between 1 and 65535\n", targetPortStr)
			os.Exit(1)
		}

		listenPort := targetPort
		if *localPort > 0 {
			if *localPort > 65535 {
				fmt.Fprintf(os.Stderr, "Error: --local-port must be between 1 and 65535\n")
				os.Exit(1)
			}
			listenPort = *localPort
		}

		// Derive gateway address from the build-time ServerURL.
		gatewayAddr := client.GatewayAddrFromServerURL(ServerURL)

		fwd := client.NewLocalForwarder(
			fmt.Sprintf("localhost:%d", listenPort),
			hostname,
			gatewayAddr,
			*insecure,
		)

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		if err := fwd.Run(ctx); err != nil {
			log.Fatalf("Forward error: %v", err)
		}

	default:
		fmt.Printf("Unknown command: %s\n", command)
		flag.Usage()
		os.Exit(1)
	}
}
