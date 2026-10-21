package secrets

import (
	"secrethandoff.com/cli/internal/policy"
	"sync"
	"testing"
)

func TestPutManyPublishesOnlyWholeGroups(t *testing.T) {
	s := NewStore()
	p, _ := policy.Parse(policy.Policy{Hosts: []string{"api.example.com"}})
	var wg sync.WaitGroup
	done := make(chan struct{})
	bad := make(chan struct{}, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				n := len(s.List())
				if n != 0 && n != 2 {
					select {
					case bad <- struct{}{}:
					default:
					}
				}
			}
		}
	}()
	for range 500 {
		if s.PutMany(map[string][]byte{"USER": []byte("dummy-user"), "PASS": []byte("dummy-pass")}, p) != nil {
			t.Fatal("valid group rejected")
		}
		s.ForgetMany([]string{"USER", "PASS"})
	}
	close(done)
	wg.Wait()
	if len(bad) != 0 {
		t.Fatal("reader observed a partially stored group")
	}
}
func TestPutManyValidatesAllBeforeChangingAnyValue(t *testing.T) {
	s := NewStore()
	p, _ := policy.Parse(policy.Policy{Hosts: []string{"api.example.com"}})
	if s.Put("USER", []byte("dummy-original"), p) != nil {
		t.Fatal("setup failed")
	}
	if s.PutMany(map[string][]byte{"USER": []byte("dummy-replacement"), "PASS": nil}, p) == nil {
		t.Fatal("empty group member accepted")
	}
	s.Use("USER", func(v []byte, _ policy.Policy) error {
		if string(v) != "dummy-original" {
			t.Fatal("invalid group changed a member")
		}
		return nil
	})
	if s.Has("PASS") {
		t.Fatal("invalid group published a member")
	}
}
