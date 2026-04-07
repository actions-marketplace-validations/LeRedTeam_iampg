// Copyright (C) 2026 LeRedTeam
// SPDX-License-Identifier: AGPL-3.0-or-later

package capture

import (
	"sync"
	"testing"

	"github.com/LeRedTeam/iampg/policy"
)

func TestCapturerNew(t *testing.T) {
	c := New()
	calls := c.Calls()
	if len(calls) != 0 {
		t.Errorf("new capturer should have 0 calls, got %d", len(calls))
	}
}

func TestCapturerAddAndRetrieve(t *testing.T) {
	c := New()
	c.AddCall(policy.ObservedCall{Service: "s3", Action: "GetObject", Resource: "arn:aws:s3:::bucket/key"})
	c.AddCall(policy.ObservedCall{Service: "dynamodb", Action: "PutItem", Resource: "arn:aws:dynamodb:*:*:table/Users"})

	calls := c.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}
	if calls[0].Service != "s3" {
		t.Errorf("first call service = %q, want s3", calls[0].Service)
	}
	if calls[1].Service != "dynamodb" {
		t.Errorf("second call service = %q, want dynamodb", calls[1].Service)
	}
}

func TestCapturerCallsReturnsCopy(t *testing.T) {
	c := New()
	c.AddCall(policy.ObservedCall{Service: "s3", Action: "GetObject"})

	calls := c.Calls()
	calls[0].Service = "modified"

	// Original should be unchanged
	original := c.Calls()
	if original[0].Service != "s3" {
		t.Error("Calls() should return a copy, not a reference to internal state")
	}
}

func TestCapturerConcurrentAccess(t *testing.T) {
	c := New()
	var wg sync.WaitGroup
	n := 100

	// Spawn n goroutines adding calls concurrently
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.AddCall(policy.ObservedCall{
				Service: "s3",
				Action:  "GetObject",
			})
		}()
	}

	// Also read concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.Calls()
		}()
	}

	wg.Wait()

	calls := c.Calls()
	if len(calls) != n {
		t.Errorf("expected %d calls after concurrent writes, got %d", n, len(calls))
	}
}
