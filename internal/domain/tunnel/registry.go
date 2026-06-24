package tunnel

// HostRegistry defines the interface for managing host authorization
// and active tunnel registration in-memory.
//
//go:generate mockery --name=HostRegistry --case=underscore --output=mocks --outpkg=mocks
type HostRegistry interface {
	Authorize(host string)
	Deauthorize(host string)
	Register(host string) bool
	Unregister(host string)
	IsAuthorized(host string) bool
	IsActive(host string) bool
	ListAllowed() []string
}
