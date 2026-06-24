---
trigger: always_on
---

# Rules for Project Unit Testing Conventions

This document outlines the testing conventions and best practices for Go unit and integration tests in the `go-tunnel` codebase.

---

## 1. Naming & Organization

### 1.1 Files and Packages
- Test files must reside in the same package as the code being tested and must end with `_test.go` (e.g., `server_test.go`).
- For external-like tests (testing public APIs), use the `_test` suffix for the package name (e.g., `package server_test`) to ensure you are only calling exported symbols.

### 1.2 Test Functions
- Test functions must start with `Test` followed by MixedCaps:
  ```go
  func TestVerifyAuthToken(t *testing.T) { ... }
  ```
- For struct method tests, name them in the format `TestStruct_Method`:
  ```go
  func TestServer_ServeHTTP(t *testing.T) { ... }
  ```

---

## 2. Table-Driven Tests (Recommended Pattern)
- Prefer table-driven tests when verifying multiple inputs, edge cases, and expected outputs.
- Use `t.Run` to wrap individual test cases so failures can be isolated and executed independently.
- Struct keys inside the test cases table must be explicitly named.

Example:
```go
func TestHostOnly(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard address with port",
			input:    "tunnel.example.com:9443",
			expected: "tunnel.example.com",
		},
		{
			name:     "address without port",
			input:    "gateway.example.com",
			expected: "gateway.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hostOnly(tt.input)
			if result != tt.expected {
				t.Errorf("hostOnly(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}
```

---

## 3. Assertions & Clean Failures
- **Testing Library**: Prefer standard library checks (`if got != want`) or `github.com/stretchr/testify/assert` / `require`.
- **Require vs Assert**:
  - Use `require` (e.g., `require.NoError(t, err)`) for assertions that must stop execution immediately (such as connection setups, initializations, or non-nil preconditions).
  - Use `assert` (e.g., `assert.Equal(t, want, got)`) for non-fatal evaluations.
- **Failures Context**: Always include clear output messages describing the input context when a test fails.

---

## 4. Isolation, Mocks, and Cleanup
- **No Shared State**: Tests must not rely on shared variables or specific execution orders.
- **Test Cleanup**: Use `t.Cleanup(func() { ... })` instead of `defer` inside tests when cleaning up files, directories, listeners, or mocking systems to keep setup code clean and structured.
- **Mock Generation with Mockery**:
  - Use `github.com/vektra/mockery/v2` to generate mock implementations for interfaces.
  - Put a `//go:generate` directive above the interface definition.
    Example:
    ```go
    //go:generate mockery --name=Store --case=underscore --output=mocks --outpkg=mocks
    ```
  - Mocks should be generated inside a `mocks/` subdirectory within the package containing the interface (e.g. `internal/tunnel/state/mocks/mock_store.go`).
  - Run `go generate ./...` to update mock files. Never modify generated mock files manually.
- **Interface Mocking**: Always verify interface behavior by using generated mocks instead of making connections to live databases (like Redis) in unit tests.


---

## 5. Parallel Execution
- Annotate unit tests with `t.Parallel()` to optimize build times and verify code concurrency safety.
- Do not use `t.Parallel()` if the test alters system-wide states (such as environment variables, directory permissions, or shared global configurations).
