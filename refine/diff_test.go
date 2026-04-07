// Copyright (C) 2026 LeRedTeam
// SPDX-License-Identifier: AGPL-3.0-or-later

package refine

import (
	"strings"
	"testing"
)

func TestDiffIdenticalPolicies(t *testing.T) {
	doc := makePolicy(
		stmt([]string{"s3:GetObject"}, "arn:aws:s3:::bucket/*"),
	)

	result := Diff(doc, doc)
	if len(result.Added) != 0 {
		t.Errorf("Added = %d, want 0", len(result.Added))
	}
	if len(result.Removed) != 0 {
		t.Errorf("Removed = %d, want 0", len(result.Removed))
	}
	if result.HasDrift() {
		t.Error("HasDrift should be false for identical policies")
	}
}

func TestDiffAddedPermissions(t *testing.T) {
	baseline := makePolicy(
		stmt([]string{"s3:GetObject"}, "arn:aws:s3:::bucket/*"),
	)
	current := makePolicy(
		stmt([]string{"s3:GetObject", "s3:PutObject"}, "arn:aws:s3:::bucket/*"),
	)

	result := Diff(baseline, current)
	if len(result.Added) != 1 {
		t.Fatalf("Added = %d, want 1", len(result.Added))
	}
	if !strings.Contains(result.Added[0].Value, "s3:PutObject") {
		t.Errorf("Added entry should contain s3:PutObject, got %q", result.Added[0].Value)
	}
	if len(result.Removed) != 0 {
		t.Errorf("Removed = %d, want 0", len(result.Removed))
	}
	if !result.HasDrift() {
		t.Error("HasDrift should be true when permissions added")
	}
}

func TestDiffRemovedPermissions(t *testing.T) {
	baseline := makePolicy(
		stmt([]string{"s3:GetObject", "s3:PutObject"}, "arn:aws:s3:::bucket/*"),
	)
	current := makePolicy(
		stmt([]string{"s3:GetObject"}, "arn:aws:s3:::bucket/*"),
	)

	result := Diff(baseline, current)
	if len(result.Removed) != 1 {
		t.Fatalf("Removed = %d, want 1", len(result.Removed))
	}
	if !strings.Contains(result.Removed[0].Value, "s3:PutObject") {
		t.Errorf("Removed entry should contain s3:PutObject, got %q", result.Removed[0].Value)
	}
	if len(result.Added) != 0 {
		t.Errorf("Added = %d, want 0", len(result.Added))
	}
}

func TestDiffAddedAndRemoved(t *testing.T) {
	baseline := makePolicy(
		stmt([]string{"s3:GetObject"}, "arn:aws:s3:::bucket/*"),
	)
	current := makePolicy(
		stmt([]string{"s3:PutObject"}, "arn:aws:s3:::bucket/*"),
	)

	result := Diff(baseline, current)
	if len(result.Added) != 1 {
		t.Errorf("Added = %d, want 1", len(result.Added))
	}
	if len(result.Removed) != 1 {
		t.Errorf("Removed = %d, want 1", len(result.Removed))
	}
}

func TestDiffDifferentResources(t *testing.T) {
	baseline := makePolicy(
		stmt([]string{"s3:GetObject"}, "arn:aws:s3:::bucket-a/*"),
	)
	current := makePolicy(
		stmt([]string{"s3:GetObject"}, "arn:aws:s3:::bucket-b/*"),
	)

	result := Diff(baseline, current)
	// Different resource = different permission entirely
	if len(result.Added) != 1 {
		t.Errorf("Added = %d, want 1", len(result.Added))
	}
	if len(result.Removed) != 1 {
		t.Errorf("Removed = %d, want 1", len(result.Removed))
	}
}

func TestDiffEmptyPolicies(t *testing.T) {
	empty := makePolicy()

	result := Diff(empty, empty)
	if result.HasDrift() {
		t.Error("HasDrift should be false for two empty policies")
	}
}

func TestDiffEmptyBaseline(t *testing.T) {
	empty := makePolicy()
	current := makePolicy(
		stmt([]string{"s3:GetObject"}, "arn:aws:s3:::bucket/*"),
	)

	result := Diff(empty, current)
	if len(result.Added) != 1 {
		t.Errorf("Added = %d, want 1", len(result.Added))
	}
}

func TestDiffEmptyCurrent(t *testing.T) {
	baseline := makePolicy(
		stmt([]string{"s3:GetObject"}, "arn:aws:s3:::bucket/*"),
	)
	empty := makePolicy()

	result := Diff(baseline, empty)
	if len(result.Removed) != 1 {
		t.Errorf("Removed = %d, want 1", len(result.Removed))
	}
}

func TestDiffMultipleStatements(t *testing.T) {
	baseline := makePolicy(
		stmt([]string{"s3:GetObject"}, "arn:aws:s3:::bucket/*"),
		stmt([]string{"dynamodb:GetItem"}, "arn:aws:dynamodb:us-east-1:123:table/Users"),
	)
	current := makePolicy(
		stmt([]string{"s3:GetObject", "s3:PutObject"}, "arn:aws:s3:::bucket/*"),
		stmt([]string{"lambda:InvokeFunction"}, "arn:aws:lambda:us-east-1:123:function:MyFunc"),
	)

	result := Diff(baseline, current)
	// Added: s3:PutObject, lambda:InvokeFunction
	// Removed: dynamodb:GetItem
	if len(result.Added) != 2 {
		t.Errorf("Added = %d, want 2", len(result.Added))
	}
	if len(result.Removed) != 1 {
		t.Errorf("Removed = %d, want 1", len(result.Removed))
	}
}

func TestDiffSortedOutput(t *testing.T) {
	baseline := makePolicy()
	current := makePolicy(
		stmt([]string{"s3:PutObject", "s3:GetObject", "s3:DeleteObject"}, "arn:aws:s3:::bucket/*"),
	)

	result := Diff(baseline, current)
	if len(result.Added) != 3 {
		t.Fatalf("Added = %d, want 3", len(result.Added))
	}
	// Should be sorted alphabetically
	for i := 1; i < len(result.Added); i++ {
		if result.Added[i].Value < result.Added[i-1].Value {
			t.Errorf("Added entries not sorted: %q < %q", result.Added[i].Value, result.Added[i-1].Value)
		}
	}
}

func TestFormatDiffNoDifferences(t *testing.T) {
	result := &DiffResult{
		Added:   []DiffEntry{},
		Removed: []DiffEntry{},
		Changed: []DiffEntry{},
	}

	output := FormatDiff(result)
	if !strings.Contains(output, "No differences found") {
		t.Error("Expected 'No differences found' in output")
	}
}

func TestFormatDiffWithChanges(t *testing.T) {
	result := &DiffResult{
		Added: []DiffEntry{
			{Type: "permission", Value: "s3:PutObject on arn:aws:s3:::bucket/*"},
		},
		Removed: []DiffEntry{
			{Type: "permission", Value: "s3:DeleteObject on arn:aws:s3:::bucket/*"},
		},
		Changed: []DiffEntry{},
	}

	output := FormatDiff(result)

	checks := []string{
		"Policy Diff",
		"Added (1)",
		"+ s3:PutObject",
		"Removed (1)",
		"- s3:DeleteObject",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("FormatDiff output missing %q", check)
		}
	}
}

func TestHasDrift(t *testing.T) {
	tests := []struct {
		name string
		diff DiffResult
		want bool
	}{
		{"no drift", DiffResult{Added: []DiffEntry{}, Removed: []DiffEntry{}, Changed: []DiffEntry{}}, false},
		{"added", DiffResult{Added: []DiffEntry{{Value: "x"}}, Removed: []DiffEntry{}, Changed: []DiffEntry{}}, true},
		{"removed", DiffResult{Added: []DiffEntry{}, Removed: []DiffEntry{{Value: "x"}}, Changed: []DiffEntry{}}, true},
		{"changed", DiffResult{Added: []DiffEntry{}, Removed: []DiffEntry{}, Changed: []DiffEntry{{Value: "x"}}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.diff.HasDrift(); got != tt.want {
				t.Errorf("HasDrift() = %v, want %v", got, tt.want)
			}
		})
	}
}
