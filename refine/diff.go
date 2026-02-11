package refine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/LeRedTeam/iampg/policy"
)

// DiffResult contains the differences between two policies.
type DiffResult struct {
	Added   []DiffEntry `json:"added"`
	Removed []DiffEntry `json:"removed"`
	Changed []DiffEntry `json:"changed"`
}

// DiffEntry represents a single difference.
type DiffEntry struct {
	Type     string `json:"type"` // action, resource
	Value    string `json:"value"`
	OldValue string `json:"old_value,omitempty"`
}

// Diff compares two policies and returns their differences.
func Diff(baseline, current *policy.Document) *DiffResult {
	result := &DiffResult{
		Added:   []DiffEntry{},
		Removed: []DiffEntry{},
		Changed: []DiffEntry{},
	}

	baselinePerms := extractPermissions(baseline)
	currentPerms := extractPermissions(current)

	// Find added permissions
	for perm := range currentPerms {
		if _, exists := baselinePerms[perm]; !exists {
			parts := strings.SplitN(perm, "|", 2)
			result.Added = append(result.Added, DiffEntry{
				Type:  "permission",
				Value: fmt.Sprintf("%s on %s", parts[0], parts[1]),
			})
		}
	}

	// Find removed permissions
	for perm := range baselinePerms {
		if _, exists := currentPerms[perm]; !exists {
			parts := strings.SplitN(perm, "|", 2)
			result.Removed = append(result.Removed, DiffEntry{
				Type:  "permission",
				Value: fmt.Sprintf("%s on %s", parts[0], parts[1]),
			})
		}
	}

	// Sort for consistent output
	sort.Slice(result.Added, func(i, j int) bool {
		return result.Added[i].Value < result.Added[j].Value
	})
	sort.Slice(result.Removed, func(i, j int) bool {
		return result.Removed[i].Value < result.Removed[j].Value
	})

	return result
}

func extractPermissions(doc *policy.Document) map[string]bool {
	perms := make(map[string]bool)
	for _, stmt := range doc.Statement {
		for _, action := range stmt.Action {
			key := action + "|" + stmt.Resource
			perms[key] = true
		}
	}
	return perms
}

// FormatDiff formats the diff result as a string.
func FormatDiff(result *DiffResult) string {
	var sb strings.Builder

	sb.WriteString("Policy Diff\n")
	sb.WriteString("===========\n\n")

	if len(result.Added) == 0 && len(result.Removed) == 0 && len(result.Changed) == 0 {
		sb.WriteString("No differences found.\n")
		return sb.String()
	}

	if len(result.Added) > 0 {
		sb.WriteString(fmt.Sprintf("Added (%d):\n", len(result.Added)))
		for _, entry := range result.Added {
			sb.WriteString(fmt.Sprintf("  + %s\n", entry.Value))
		}
		sb.WriteString("\n")
	}

	if len(result.Removed) > 0 {
		sb.WriteString(fmt.Sprintf("Removed (%d):\n", len(result.Removed)))
		for _, entry := range result.Removed {
			sb.WriteString(fmt.Sprintf("  - %s\n", entry.Value))
		}
		sb.WriteString("\n")
	}

	if len(result.Changed) > 0 {
		sb.WriteString(fmt.Sprintf("Changed (%d):\n", len(result.Changed)))
		for _, entry := range result.Changed {
			sb.WriteString(fmt.Sprintf("  ~ %s -> %s\n", entry.OldValue, entry.Value))
		}
	}

	return sb.String()
}

// HasDrift returns true if there are any differences.
func (d *DiffResult) HasDrift() bool {
	return len(d.Added) > 0 || len(d.Removed) > 0 || len(d.Changed) > 0
}
