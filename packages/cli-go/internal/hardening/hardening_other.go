//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd

package hardening

// Windows does not write core dumps by default. Nothing to do.
func apply() []error { return nil }
