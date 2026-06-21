# Setting Up Free Wildcard SSL with Cloudflare

This guide explains how to generate and configure a free, long-lived Wildcard SSL certificate using Cloudflare's Origin CA for the `go-tunnel` project.

Cloudflare provides free **Origin Certificates** that can last up to 15 years. These certificates encrypt traffic between your server and Cloudflare's Edge network.

---

## Step 1: Add Your Domain to Cloudflare
1. Create a free account at [Cloudflare](https://dash.cloudflare.com/).
2. Click **Add a Site** and enter your domain name (e.g., `example.com`).
3. Select the **Free plan**.
4. Cloudflare will scan your existing DNS records. Review them and click **Continue**.
5. Change your domain's nameservers at your domain registrar to the Cloudflare nameservers provided.

---

## Step 2: Generate the Wildcard Certificate
Once your domain is active on Cloudflare:
1. In the Cloudflare Dashboard, go to **SSL/TLS** -> **Origin Server**.
2. Click **Create Certificate**.
3. Keep **"Let Cloudflare generate a private key and a CSR"** selected.
4. In the **Hostnames** field, ensure both your root domain and the wildcard are listed. For example:
   - `example.com`
   - `*.example.com`
5. Set the **Certificate Validity** (e.g., 15 years).
6. Click **Create**.

> [!WARNING]
> You will now see your **Origin Certificate** and **Private Key**. You must copy the Private Key now, as Cloudflare will never show it to you again!

### Save the Certificate Files
On your VPS/Server, create two files and paste the contents provided by Cloudflare:

1. **Certificate (`fullchain.pem`)**
   Create a file named `cloudflare-cert.pem` and paste the "Origin Certificate" text.
2. **Private Key (`privkey.pem`)**
   Create a file named `cloudflare-key.pem` and paste the "Private Key" text.

---

## Step 3: Configure Cloudflare SSL Mode
For the Origin Certificate to work, you must enforce strict SSL mode:
1. Go to **SSL/TLS** -> **Overview**.
2. Set the encryption mode to **Full (strict)**. 
*(This ensures Cloudflare verifies your Origin Certificate before passing traffic).*

---

## Step 4: Configure `go-tunnel`

Now, update your `.env` file in the `go-tunnel` project to use these certificates. **Keep ACME (Let's Encrypt) enabled!** This allows `go-tunnel` to dynamically serve the Cloudflare wildcard certificate for all subdomains, while simultaneously fetching free Let's Encrypt certificates automatically if you ever map custom external domains (e.g., `myapp.com`).

```env
# Keep Let's Encrypt enabled for custom external domains
ACME_ENABLE=true

# Define the wildcard pattern
WILDCARD_DOMAIN=*.example.com

# Point to the files you saved in Step 2 for the wildcard
WILDCARD_CERT_PATH=/path/to/cloudflare-cert.pem
WILDCARD_KEY_PATH=/path/to/cloudflare-key.pem
```

If you are using Docker/Podman to run the application, make sure to mount the certificate files into the container, or place them inside a directory that is already mapped (like `cert-cache`), and update the `.env` paths accordingly.

---

## Step 5: DNS Configuration & Routing Rules

This is the most critical step due to the architecture of `go-tunnel`. The proxy uses **SNI Multiplexing** to separate raw TCP Tunnel traffic from standard HTTP traffic.

### 1. HTTP/Web Traffic (Orange Cloud - Proxied)
You can use Cloudflare's proxy (Orange Cloud) for the Web UI and standard web applications hosted through the tunnel. Cloudflare will terminate the public SSL and forward it securely using the Origin Cert.

In Cloudflare **DNS**, add the following records and set them to **Proxied (Orange Cloud)**:
| Type  | Name | Target | Proxy Status |
| ----- | ---- | ------ | ------------ |
| A | `gateway` | `YOUR_SERVER_IP` | 🟧 Proxied |
| A | `webui` | `YOUR_SERVER_IP` | 🟧 Proxied |
| CNAME | `*` | `gateway.example.com` | 🟧 Proxied |

### 2. Tunnel Agent Traffic (Grey Cloud - DNS Only)
> [!IMPORTANT]  
> Cloudflare's free proxy **only supports HTTP/HTTPS**. It **DOES NOT** support routing raw TCP streams like the Yamux protocol used by the `go-tunnel` agent.

To allow the Go-Tunnel agents to connect to the server via Port 443, the tunnel domain **must bypass Cloudflare's proxy**.

Add this record and set it to **DNS Only (Grey Cloud)**:
| Type  | Name | Target | Proxy Status |
| ----- | ---- | ------ | ------------ |
| A | `tunnel` | `YOUR_SERVER_IP` | ☁️ DNS Only |

### 3. Agent Client Configuration
Because `tunnel.example.com` connects directly to your server (bypassing Cloudflare), the agent will receive the **Cloudflare Origin Certificate**. By default, standard operating systems do not trust Cloudflare's Origin Root CA.

To fix this, you must configure the Go-Tunnel Client to skip TLS verification for the connection. In the client's `config.yaml`, ensure this is set:

```yaml
skip_tls_verify: true
```
*(Note: If you download the client binary directly from the Web UI Manager, this flag is automatically configured for you based on the server's environment settings).*
