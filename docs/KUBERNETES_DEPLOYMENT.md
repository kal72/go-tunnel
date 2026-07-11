# Kubernetes Deployment Guide (Pods & Horizontal Scaling)

This document explains the architecture and deployment procedures for `go-tunnel` within **Kubernetes Pods** (`Deployment`, `StatefulSet`, `Service`, `LoadBalancer`).

Because the `gotunnel-server` binary does not perform *Inter-Pod Mesh Routing* (looking up active Yamux sessions across RAM in other pods), our Kubernetes deployment utilizes an **"Edge Proxy Scaling + Core Gateway Sharding"** topology that cleanly separates workload layers so **you never encounter `502 Bad Gateway` errors**.

---

## 1. Pod Topology & Architecture

```
[ Public Internet / Web & Minecraft Visitors ]
                       |
            (Port 80 & 443 - Public IP)
                       v
     +-----------------------------------+
     |   Service LoadBalancer (K8s LB)   |
     +-----------------------------------+
                       |
       +---------------+---------------+
       v               v               v
 [Pod Proxy 1]   [Pod Proxy 2]   [Pod Proxy 3]  <--- Stateless Edge Deployment (Replicas: 3+)
       |               |               |             * Handles TLS Termination, SNI, ACME
       +---------------+---------------+
                       |
     +-----------------+-----------------+
     |                                   |
     | (TUNNEL_TARGET: http://8443)      | (WEBUI_TARGET: http://8080)
     v                                   v
+-----------------------------+     +-----------------------------+
|    Service: gotunnel-core   |     |   Service: gotunnel-webui   |
+-----------------------------+     +-----------------------------+
     |                                   |
     v                                   v
[Pod Core Gateway (StatefulSet)]    [Pod Web UI Dashboard]
 * Holds active Yamux conns (9443)       * Account & API Token Management
 * Stores Active Domain Locks in Redis   * Connected to Redis / Postgres
```

### Why This Topology Works Without Inter-Pod Routing
1. **Edge Proxy (`gotunnel-proxy`) is 100% Stateless**: The front-facing proxy pods do not hold TCP/Yamux sockets in their local memory. Consequently, you can scale out the proxy pods from 3 to 20+ replicas without synchronizing state across nodes.
2. **Yamux Streams Terminate at Core Gateway (`gotunnel-core`)**: All front-facing proxy pods forward incoming HTTP traffic and internal tunnel calls to a single unified Kubernetes Service endpoint (`gotunnel-core.default.svc.cluster.local:8443`). Piped Yamux streams and HTTP requests rendezvous inside the exact same Core Pod memory.

---

## 2. Manifest Structure (`deploy/kubernetes/`)

The [`deploy/kubernetes/`](file:///Users/kal/Projects/go-tunnel/deploy/kubernetes) folder provides 5 production-ready YAML manifests:

| Manifest File | K8s Resource Type | Description |
| :--- | :--- | :--- |
| **`01-configmap.yaml`** | `ConfigMap` | Stores domain configurations (`GATEWAY_DOMAIN`, `TUNNEL_DOMAIN`), internal port definitions, and target K8s Service URLs. |
| **`02-redis.yaml`** | `Deployment` + `Service` | Provisions a Redis ClusterIP pod for *Shared State*, active domain locking (`active_domain:*`), and rate limit tracking. |
| **`03-core-gateway.yaml`** | `StatefulSet` + `Service` | Runs the `gotunnel-tunnel` binary on ports `8443` & `9443` as the internal Core Gateway service. |
| **`04-webui.yaml`** | `Deployment` + `Service` | Runs the `gotunnel-webui` dashboard on port `8080` for user management and telemetry monitoring. |
| **`05-edge-proxy.yaml`** | `Deployment` (`replicas: 3`) + `Service LoadBalancer` | Runs 3 `gotunnel-proxy` pods listening on public ports (`80` & `443`) as the primary cluster gateway. |

---

## 3. Deployment Steps

### Step 1: Configure Domains in ConfigMap
Edit [`deploy/kubernetes/01-configmap.yaml`](file:///Users/kal/Projects/go-tunnel/deploy/kubernetes/01-configmap.yaml) and replace the placeholder domains with your actual domain names:
```yaml
data:
  GATEWAY_DOMAIN: "gate.yourdomain.com"
  TUNNEL_DOMAIN: "tunnel.yourdomain.com"
  WEBUI_DOMAIN: "app.yourdomain.com"
```

### Step 2: Apply Manifests to Kubernetes
Run `kubectl apply` sequentially or across the entire directory:
```bash
kubectl apply -f deploy/kubernetes/01-configmap.yaml
kubectl apply -f deploy/kubernetes/02-redis.yaml
kubectl apply -f deploy/kubernetes/03-core-gateway.yaml
kubectl apply -f deploy/kubernetes/04-webui.yaml
kubectl apply -f deploy/kubernetes/05-edge-proxy.yaml
```

### Step 3: Verify Pods & Service Status
Check whether all pods reach the `Running` state:
```bash
kubectl get pods -l 'app in (gotunnel-proxy, gotunnel-core, gotunnel-webui, gotunnel-redis)'
```
Expected output example:
```
NAME                              READY   STATUS    RESTARTS   AGE
gotunnel-core-0                   1/1     Running   0          2m
gotunnel-proxy-6d8b9487c5-7xk2q   1/1     Running   0          2m
gotunnel-proxy-6d8b9487c5-9pj8w   1/1     Running   0          2m
gotunnel-proxy-6d8b9487c5-m4z2l   1/1     Running   0          2m
gotunnel-redis-5c87d69b9f-lk29a   1/1     Running   0          2m
gotunnel-webui-8695d7f6b4-w9s8c   1/1     Running   0          2m
```

Retrieve the External IP assigned by the LoadBalancer Service and configure your domain `A Records` in DNS:
```bash
kubectl get svc gotunnel-proxy-lb
```

---

## 4. Horizontal Pod Autoscaling (HPA) for Edge Proxy

Because `gotunnel-proxy` pods are entirely stateless, you can enable a **Horizontal Pod Autoscaler (HPA)** so proxy pods automatically scale out during traffic surges or mild DDoS attacks:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: gotunnel-proxy-hpa
  namespace: default
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: gotunnel-proxy
  minReplicas: 3
  maxReplicas: 20
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

---

## 5. Frequently Asked Questions (FAQ)

### Q: Why does `gotunnel-core` use a `StatefulSet` rather than a standard `Deployment`?
Because `gotunnel-core` holds persistent Yamux socket connections (`net.Conn`) from remote PC agents inside kernel memory. A `StatefulSet` guarantees predictable lifecycle management (`graceful termination & network identity`) during rolling updates and node maintenance, preventing sudden disconnection of active client agents.

### Q: How can I run the All-in-One Mode (`start.sh`) inside a single K8s Pod?
Simply replace `command: ["./gotunnel-proxy"]` in the container specification with `command: ["./start.sh"]` (or omit the `command` field completely). However, for robust horizontal scaling in Kubernetes, the separated topology (*Edge Proxy + Core Gateway*) detailed above is strongly recommended.
