---
trigger: always_on
---

# Rules for Project Coding Conventions & Best Practices

This document defines the coding style, layout, naming rules, and development patterns for Go implementation in the `go-tunnel` project.

---

## 1. Naming Conventions

### 1.1 Package Names
- Package names must be lowercase, short, and contain a single word.
- Do not use underscores or camelCase.
- Example: `config` (Good), `server_config` (Avoid), `serverConfig` (Avoid).

### 1.2 Structs and Interfaces
- Use **MixedCaps** (CamelCase) for naming structs, interfaces, and custom types.
- Exported types start with an uppercase letter (`Client`), unexported types start with a lowercase letter (`dashItem`).
- Interfaces should end with "-er" if they represent a single action (e.g., `Store`, `Reader`, `Writer`).

### 1.3 Variables and Constants
- Use `mixedCaps` (camelCase) instead of snake_case for variable names.
- Keep variable names short and concise, especially when their scope is narrow:
  - Use `err` for errors, `ctx` for context, `cfg` for configurations, `h` for handlers, `ln` for listeners.
- Constants should use MixedCaps if exported (e.g. `MsgTypePing`) or mixedCaps if private. Avoid using ALL_CAPS.

### 1.4 Receiver Names
- Keep struct receivers short (typically 1 or 2 characters matching the type name).
- Do not use generic words like `this` or `self`.
- Example:
  ```go
  func (s *Server) ServeHTTP(...) // Good: s corresponds to Server
  func (this *Server) ServeHTTP(...) // Avoid
  ```

---

## 2. Code Structure & Layout

### 2.1 Import Grouping
Organize package imports into three distinct groups, separated by blank lines:
1. Standard library imports.
2. Third-party dependency imports.
3. Internal project imports.

Example:
```go
import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"

	"gotunnel/internal/tunnel/config"
	"gotunnel/internal/tunnel/state"
)
```

### 2.2 Control Flow (Left-Align the Happy Path)
- Minimize indentation by using early exit/return patterns and guard clauses.
- Keep the successful execution flow (the "happy path") aligned to the left of the function.
- Example:
  ```go
  // Good (Left-Aligned Happy Path)
  if err != nil {
      return err
  }
  // execution continues left-aligned

  // Avoid (Deep Nesting)
  if err == nil {
      // main logic nested here
  }
  ```

---

## 3. Idiomatic Go Practices

### 3.1 Slices and Maps Initialization
- Prefer `nil` slices over empty slices unless JSON serialization requires an empty array `[]`.
  - Prefer: `var hosts []string`
  - Avoid: `hosts := []string{}` (unless empty serialization is explicitly required by the API schema).
- Pre-allocate map or slice capacities using `make(type, capacity)` if the length or capacity is known in advance.

### 3.2 Constructor Functions
- Provide constructor functions (usually prefixed with `New`) for types requiring initialization or default configurations:
  ```go
  func NewServer(cfg *config.ServerConfig) *Server {
      return &Server{
          cfg:       cfg,
          hostToSes: make(map[string]*TunnelSession),
      }
  }
  ```

### 3.3 Dependency Inversion Principle (DIP) & Mocks
- Rely on interfaces rather than concrete implementations for external dependencies or complex internal services.
- This decoupling is required to support the generation of mocks (e.g., using `mockery`) for unit tests.
- Define interfaces where they are used (consumer side) when possible, ensuring they are small and single-purpose.

---

## 4. Documentation & Comments
- All comments must be written in **English**.
- Every exported identifier (structs, functions, methods, packages) must have a doc comment matching standard Go doc rules:
  ```go
  // Server handles the reverse proxying and client tunnel sessions.
  type Server struct { ... }
  ```
- Comments should explain the **why** of non-obvious code paths, rather than simply restating the **what**.

---

## 5. Security & Concurrency Safety
- **Zero Global State**: Avoid global variables for session states or database links. Pass dependencies explicitly through structs or interfaces.
- **Panic Protection**: Never spawn a background goroutine without a deferred panic recovery block to ensure the main binary does not crash due to unhandled exceptions.
- **Short-Lived Locks**: Guard shared memory using mutexes (`sync.Mutex` or `sync.RWMutex`). Never issue database queries or network requests while holding locks.