## Go Tunnel Performance Snapshot

| Layer / Component      | Metric / Behavior                      | Estimated Capacity / Cost                 | Current Limitation / Notes                                                                 |
|------------------------|----------------------------------------|-------------------------------------------|--------------------------------------------------------------------------------------------|
| HTTP reverse proxy     | Throughput                             | ~1.5–2.5k req/s per server (2 vCPU)       | Each request opens a fresh Yamux stream; latency dominated by agent RTT.                   |
|                        | Added latency                          | +4–8 ms intra-region, +20–40 ms inter     | Includes TLS → Yamux → local TCP hops; no caching/keep-alive across requests.              |
| Raw TCP tunnels        | Connection handling                    | 800–1200 new conn/s (4 KB blocks)         | Requires HTTP/1.1 hijacking; HTTP/2 requests must be routed via `mode=http`.               |
|                        | Aggregate bandwidth                    | 1.0–1.2 Gbps (default buffers)            | Yamux flow window is ~32 KB; increase to push higher throughput.                           |
| Control plane          | Register handshake time                | <5 ms                                     | Only JSON parsing; cost rises linearly with number of declared hosts.                      |
|                        | Heartbeat overhead                     | 1 goroutine per client, 15 s ping cadence | Scale comfortably up to ~5k clients; for more, switch to shared ticker or event loops.     |
| Host/session registry  | Memory footprint                       | 60–80 MB per 1k active hosts              | `hostToSes` guarded by global RWMutex; consider sharding if lock contention appears.       |
| Dashboard              | Render cost                            | O(hosts); a few ms for hundreds of hosts  | For thousands of hosts, add pagination or cache the HTML snapshot between requests.        |
