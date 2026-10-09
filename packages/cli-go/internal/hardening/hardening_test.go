package hardening

import "testing"

func TestApply(t *testing.T) {
	if errs := Apply(); len(errs) != 0 {
		t.Fatalf("Apply: %v", errs)
	}
}
