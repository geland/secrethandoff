// Package hardening applies process protections that reduce how a same-user
// process can read the binary's memory (threat model T-23, T-24).
package hardening

// Apply disables core dumps and, where the OS allows, marks the process as
// not dumpable. It is best effort and returns the steps that failed.
func Apply() []error { return apply() }
