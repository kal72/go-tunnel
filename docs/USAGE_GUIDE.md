# Go-Tunnel Usage Guide (Client)

This documentation explains the steps to connect your local services to the internet using `go-tunnel`, from server-side configuration (Web UI) to running the client.

## 1. Web UI Preparation (Server)

Before the client can connect, you must set up access and register subdomains on the server via the Web UI.

1. **Login to Web UI**: Access the management dashboard in your browser (default port `8080`). Use your credentials (default: `admin` / `admin123`).
2. **Register Subdomain**:
   - Go to the **Domain Manager** menu.
   - Manually add the subdomain you want to use (e.g., `app.yourvps.com`), or use the *Generate Random* feature to create a random subdomain.
3. **Generate Auth Token**:
   - Go to the **Token Management** or **Client Config** menu.
   - Create a new token for your device by entering a *Client ID* (e.g., `office-laptop`).
   - Copy the generated **Auth Token**. This token will be used in the client configuration.

> [!IMPORTANT]
> Ensure the subdomain you register matches the `WILDCARD_DOMAIN` or has been correctly pointed (CNAME/A Record) in your DNS settings.

---

## 2. Creating the Configuration File (Client)

On the local/client computer, you need to create a YAML format configuration file.

1. Create a file named `config.yaml` in the same directory as the client application. (You can also copy from `config.yaml.example`).
2. Fill the file with the following format:

```yaml
# Connection to the tunnel listener on the VPS server
tunnel_addr: "tunnel.yourvps.com:9443"
skip_tls_verify: false

# Authentication from Web UI
client_id: "office-laptop"
auth_token: "paste-token-from-dashboard"

# Mapping host -> local target
tunnels:
  # Example for HTTP service (Web)
  - hostname: "app.yourvps.com"
    target: "127.0.0.1:8080"
    mode: "http"
    
  # Example for raw TCP service (e.g., SSH or Database)
  - hostname: "ssh.yourvps.com"
    target: "127.0.0.1:22"
    mode: "tcp"
```

**Configuration Explanation:**
- `tunnel_addr`: The address and port of your tunnel server.
- `client_id`: A unique identifier for this client.
- `auth_token`: The token copied from the Web UI earlier.
- `tunnels`: A list of local services you want to expose. Ensure the `hostname` is already registered in the Web UI Domain Manager. `target` is the address of your local service currently running.

---

## 3. Running the Client & Connecting to the Tunnel

After the configuration is complete, you are ready to connect the client to the server.

Run the following command in your local computer's terminal:

```bash
go run ./cmd/client/main.go
```
*(If you are using a pre-built binary, simply run the executable, e.g.: `./go-tunnel-client`)*

**Process breakdown:**
1. The client reads `config.yaml`.
2. It establishes a TLS connection to `tunnel_addr`.
3. It sends the `client_id` and `auth_token` for server validation (via Redis).
4. Upon success, the tunnel opens. Internet traffic directed to the `hostname` (e.g., `app.yourvps.com`) will be automatically forwarded to the local `target` (e.g., `127.0.0.1:8080`).

> [!TIP]
> If you encounter issues with local SSL/TLS connections using self-signed certificates during testing, you can set `skip_tls_verify: true` in the configuration, though this is **not recommended** for production environments.

---

## 4. Local Port Forwarding (`gotunnel forward`)

To access raw TCP services (such as **Windows RDP**, **Database**, **VNC**, or **SSH**) from your computer without needing VPN or extra tools like `stunnel`, use the `gotunnel forward` subcommand.

All traffic flows securely encrypted over port **443 (HTTPS)** directly to the go-tunnel gateway and is relayed to your active tunnel.

### Requirements:
1. You must have logged in (`gotunnel login`) or configured `GOTUNNEL_TOKEN`.
2. The target service must be already running and exposed via `mode: tcp` in the agent configuration (e.g., `rdp.yourvps.com` -> `127.0.0.1:3389`).

### Usage Examples:

```bash
# Forward remote Windows RDP to localhost:3389
gotunnel forward rdp.yourvps.com 3389
# -> Open your RDP client and connect to localhost:3389

# Forward remote PostgreSQL Database to localhost:5432
gotunnel forward db.yourvps.com 5432
# -> Open DBeaver or TablePlus and connect to localhost:5432

# Forward remote MySQL Database to localhost:3306
gotunnel forward mysql.yourvps.com 3306

# Use a custom local port (e.g., listen on localhost:13389 forwarding to remote port 3389)
gotunnel forward --local-port 13389 rdp.yourvps.com 3389
```

---

## 5. Monitoring & Management


- **View Status**: You can monitor the real-time status of connected devices in the **Dashboard** menu on the Web UI. You will see the Client ID, source IP, mapped hostnames, and connection time.
- **Disconnecting**: If you need to forcibly disconnect a client, go to the Token Management menu and click **Revoke**. The client connection will be immediately terminated, and the token will no longer be valid.
