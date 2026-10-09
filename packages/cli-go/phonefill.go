package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"secrethandoff.com/cli/internal/localpage"
	"secrethandoff.com/cli/internal/policy"
	"secrethandoff.com/cli/internal/relay"
)

const defaultRelayURL = "https://secrethandoff.com"

func relayURLFromEnv() string {
	if v := os.Getenv("SECRETHANDOFF_RELAY_URL"); v != "" {
		return v
	}
	return defaultRelayURL
}

// startPhoneFill creates a relay request when the human presses "Fill on
// my phone instead" (ADR 0010). Local mode alone never contacts the
// service. The QR code and pairing code go only to the local page.
func (s *session) startPhoneFill(reason string, p policy.Policy, ttl time.Duration, local *localpage.Request) (localpage.RelayInfo, error) {
	client, err := relay.NewClient(s.relayURL)
	if err != nil {
		return localpage.RelayInfo{}, err
	}
	policyJSON, _ := json.Marshal(p)
	if ttl > relay.MaxLifetime {
		ttl = relay.MaxLifetime
	}
	r, err := relay.New(string(policyJSON), ttl)
	if err != nil {
		return localpage.RelayInfo{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.Create(ctx, r, reason); err != nil {
		return localpage.RelayInfo{}, err
	}
	link := r.Link(s.relayURL)
	svg, err := relay.QRSVG(link)
	if err != nil {
		return localpage.RelayInfo{}, err
	}
	go s.pollPhoneFill(client, r, local)
	return localpage.RelayInfo{QRSVG: svg, PairingCode: relay.PairingCode(r.PublicKey()), Link: link}, nil
}

// pollPhoneFill waits for the phone, then completes the local request. If
// the local page wins first, it cancels the relay request.
func (s *session) pollPhoneFill(client *relay.Client, r *relay.Request, local *localpage.Request) {
	deadline := time.Unix(r.Expires, 0)
	wait := 2 * time.Second
	failures := 0
	for time.Now().Before(deadline) {
		select {
		case <-local.Done():
			// Filled here, declined, cancelled, or expired: the relay
			// request is no longer needed.
			_ = client.Cancel(context.Background(), r)
			return
		case <-time.After(wait):
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		value, err := client.Pickup(ctx, r)
		cancel()
		switch {
		case errors.Is(err, relay.ErrPending):
			failures = 0
			if wait < 5*time.Second {
				wait += time.Second
			}
			continue
		case errors.Is(err, relay.ErrUnreachable) && failures < 5:
			// Network trouble: keep trying with a longer wait.
			failures++
			wait = time.Duration(failures*5) * time.Second
			continue
		case err != nil:
			local.RelayFailed(err.Error())
			_ = client.Cancel(context.Background(), r)
			return
		}
		if err := local.FillExternal(value); err != nil {
			local.RelayFailed("the phone fill arrived after the request ended")
		}
		return
	}
	local.RelayFailed("the phone request expired")
}
