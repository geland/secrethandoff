// Package secrets holds secrets in process memory and removes them from any
// text before that text leaves the binary (ADR 0009, AGENTS.md invariants).
package secrets

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"

	"secrethandoff.com/cli/internal/policy"
)

// NamePattern limits secret names to identifiers that are safe to show to
// the model and to use in {{secret:NAME}} references.
var NamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// Info describes a secret without its value. It is safe to return to the model.
type Info struct {
	Name     string        `json:"name"`
	Policy   policy.Policy `json:"policy"`
	FilledAt time.Time     `json:"filled_at"`
}

type entry struct {
	value []byte
	info  Info
}

// Store holds filled secrets in memory only. It never writes to disk.
type Store struct {
	mu    sync.RWMutex
	items map[string]*entry
}

func NewStore() *Store { return &Store{items: map[string]*entry{}} }

// Put stores a copy of value. A later Put with the same name replaces the
// earlier secret and erases its value.
func (s *Store) Put(name string, value []byte, p policy.Policy) error {
	if !NamePattern.MatchString(name) {
		return fmt.Errorf("invalid secret name %q", name)
	}
	if len(value) == 0 {
		return errors.New("empty secret")
	}
	v := make([]byte, len(value))
	copy(v, value)
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.items[name]; ok {
		wipe(old.value)
	}
	s.items[name] = &entry{value: v, info: Info{Name: name, Policy: p, FilledAt: time.Now().UTC()}}
	return nil
}

// Use calls fn with the secret value and its policy. The value must not
// escape fn. Callers must pass any text that leaves the binary through a
// Redactor.
func (s *Store) Use(name string, fn func(value []byte, p policy.Policy) error) error {
	s.mu.RLock()
	e, ok := s.items[name]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no secret named %q; call request_secret first", name)
	}
	return fn(e.value, e.info.Policy)
}

// Has reports whether a secret with this name is filled.
func (s *Store) Has(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.items[name]
	return ok
}

// List returns every secret's name and policy, sorted by name. Never values.
func (s *Store) List() []Info {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Info, 0, len(s.items))
	for _, e := range s.items {
		out = append(out, e.info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Forget erases a secret. It reports whether the secret existed.
func (s *Store) Forget(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.items[name]
	if ok {
		wipe(e.value)
		delete(s.items, name)
	}
	return ok
}

// ForgetAll erases every secret, for example when the session ends.
func (s *Store) ForgetAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, e := range s.items {
		wipe(e.value)
		delete(s.items, name)
	}
}

// Redactor returns a redactor for every secret held now.
func (s *Store) Redactor() *Redactor {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := &Redactor{}
	for name, e := range s.items {
		r.add(name, e.value)
	}
	r.sort()
	return r
}

// wipe overwrites a value. Go may still hold copies made by the runtime, so
// this is best effort, not a guarantee.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
