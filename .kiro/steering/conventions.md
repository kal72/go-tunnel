---
inclusion: always
---

# Code Conventions: go-tunnel

## Naming

### Packages
- Lowercase, single word, no underscores: `config`, `handler`, `ratelimit` ✓
- Not: `server_config`, `serverConfig` ✗

### Structs & interfaces
- `MixedCaps` (CamelCase). Exported starts uppercase, unexported starts lowercase.
- Single-method interfaces: use "-er" suffix where natural (`Store`, `Reader`, `HostRegistry`).

### Variables & constants
- `camelCase`, not `snake_case`. Keep names short when scope is narrow.
- Standard shorthands: `err`, `ctx`, `cfg`, `h` (handler), `ln` (listener), `s` (server receiver).
- Constants: `MixedCaps` if exported (`MsgTypePing`), `mixedCaps` if private. No `ALL_CAPS`.

### Receiver names
- 1–2 characters matching the type: `s` for `*Server`, `h` for `*Handler`, `u` for `*authUsecase`.
- Never use `this` or `self`.

---

## Import Grouping

Always three groups, separated by blank lines:

```go
import (
    // 1. Standard library
    "context"
    "fmt"
    "net/http"

    // 2. Third-party
    "github.com/go-chi/chi/v5"
    "github.com/redis/go-redis/v9"

    // 3. Internal
    "gotunnel/internal/config"
    "gotunnel/internal/domain/tunnel"
)
```

---

## Control Flow

**Left-align the happy path** using early returns and guard clauses. Avoid deep nesting.

```go
// Good
if err != nil {
    return err
}
// happy path continues here at left margin

// Avoid
if err == nil {
    // main logic deeply nested
}
```

---

## Constructors

Always provide a `New*` constructor for types requiring initialization:

```go
func NewServer(cfg *config.ServerConfig) *Server {
    return &Server{
        cfg:       cfg,
        hostToSes: make(map[string]*TunnelSession),
        logger:    logger,
    }
}
```

---

## Slices & Maps

- Prefer `nil` slices over empty slice literals unless JSON must serialize as `[]`:
  - `var hosts []string` ✓
  - `hosts := []string{}` — only when empty JSON array is explicitly required
- Pre-allocate with `make(type, capacity)` when size is known.

---

## Dependency Inversion

- Depend on interfaces, not concrete types, for external dependencies.
- Define interfaces at the **consumer** side (where they are used), not in the implementation package.
- This enables mockery-generated mocks for unit tests without real Redis/PostgreSQL.

---

## Concurrency & Safety

- **No global state**: session state, DB connections, and stores are always passed through structs/interfaces.
- **Panic recovery**: every goroutine spawned in the background must have `defer func() { _ = recover() }()`.
- **Short-lived locks**: never make DB or network calls while holding a `sync.Mutex` or `sync.RWMutex`.

```go
// Good: read under lock, then release before I/O
s.mu.RLock()
val := s.cachedData
s.mu.RUnlock()
// use val after releasing the lock

// Avoid: holding lock during DB query
s.mu.Lock()
result, err := s.db.Query(ctx, ...)  // ← I/O under lock
s.mu.Unlock()
```

---

## Error Wrapping

Wrap errors with context using `fmt.Errorf("operation: %w", err)`. Never swallow errors silently unless there is an explicit documented reason.

---

## Documentation & Comments

- All comments in **English**.
- Every exported identifier must have a doc comment matching Go conventions:
  ```go
  // Server manages active Yamux tunnel sessions and HTTP demultiplexing.
  type Server struct { ... }
  ```
- Comments explain **why**, not just what. Restate-the-code comments are noise.

---

## Logging

Use `go.uber.org/zap` (structured logging) in server components. Use `log.Printf` only in `cmd/` entry points and `di/` wiring code. Never use `fmt.Println` in production server paths.

```go
s.logger.Error("failed to update tunnel state", zap.Error(err))
s.logger.Info("new tunnel connected", zap.String("addr", ip))
```

---

## Mock Generation

- Use `//go:generate mockery --name=<Interface>` directive above each interface.
- Generated mocks live in a `mocks/` subdirectory beside the interface file.
- Never edit generated mock files manually.
- Run `make generate` (which calls `mockery`) to regenerate all mocks.

Domain interface mock locations:
- `internal/domain/tunnel/mocks/`
- `internal/domain/user/mocks/`
- `internal/domain/config/mocks/`
- `internal/domain/setting/mocks/`
- `internal/usecase/*/mocks/`
