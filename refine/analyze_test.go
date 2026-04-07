// Copyright (C) 2026 LeRedTeam
// SPDX-License-Identifier: AGPL-3.0-or-later

package refine

import (
	"strings"
	"testing"

	"github.com/LeRedTeam/iampg/policy"
)

func makePolicy(statements ...policy.Statement) *policy.Document {
	return &policy.Document{
		Version:   "2012-10-17",
		Statement: statements,
	}
}

func stmt(actions []string, resource string) policy.Statement {
	return policy.Statement{
		Effect:   "Allow",
		Action:   actions,
		Resource: resource,
	}
}

func TestAnalyzeCleanPolicy(t *testing.T) {
	doc := makePolicy(
		stmt([]string{"s3:GetObject"}, "arn:aws:s3:::my-bucket/*"),
	)

	result := Analyze(doc)
	if len(result.Issues) != 0 {
		t.Errorf("Expected 0 issues, got %d: %+v", len(result.Issues), result.Issues)
	}
	if result.Summary.TotalStatements != 1 {
		t.Errorf("TotalStatements = %d, want 1", result.Summary.TotalStatements)
	}
	// Clean policy should get the "follows least-privilege" suggestion
	found := false
	for _, s := range result.Suggestions {
		if strings.Contains(s, "least-privilege") {
			found = true
		}
	}
	if !found {
		t.Error("Expected least-privilege suggestion for clean policy")
	}
}

func TestAnalyzeWildcardActionStar(t *testing.T) {
	doc := makePolicy(
		stmt([]string{"*"}, "arn:aws:s3:::my-bucket/*"),
	)

	result := Analyze(doc)
	if result.Summary.WildcardActions != 1 {
		t.Errorf("WildcardActions = %d, want 1", result.Summary.WildcardActions)
	}

	found := false
	for _, issue := range result.Issues {
		if issue.Type == "wildcard-action" && issue.Severity == "error" {
			found = true
		}
	}
	if !found {
		t.Error("Expected error-level wildcard-action issue for *")
	}
}

func TestAnalyzeServiceWildcard(t *testing.T) {
	doc := makePolicy(
		stmt([]string{"s3:*"}, "arn:aws:s3:::my-bucket/*"),
	)

	result := Analyze(doc)
	if result.Summary.WildcardActions != 1 {
		t.Errorf("WildcardActions = %d, want 1", result.Summary.WildcardActions)
	}

	found := false
	for _, issue := range result.Issues {
		if issue.Type == "wildcard-action" && issue.Severity == "warning" {
			found = true
		}
	}
	if !found {
		t.Error("Expected warning-level wildcard-action issue for s3:*")
	}
}

func TestAnalyzePartialWildcard(t *testing.T) {
	doc := makePolicy(
		stmt([]string{"s3:Get*"}, "arn:aws:s3:::my-bucket/*"),
	)

	result := Analyze(doc)

	found := false
	for _, issue := range result.Issues {
		if issue.Type == "wildcard-action" && issue.Severity == "info" {
			found = true
		}
	}
	if !found {
		t.Error("Expected info-level wildcard-action issue for s3:Get*")
	}
}

func TestAnalyzeWildcardResource(t *testing.T) {
	doc := makePolicy(
		stmt([]string{"s3:GetObject"}, "*"),
	)

	result := Analyze(doc)
	if result.Summary.WildcardResources != 1 {
		t.Errorf("WildcardResources = %d, want 1", result.Summary.WildcardResources)
	}

	found := false
	for _, issue := range result.Issues {
		if issue.Type == "wildcard-resource" && issue.Severity == "error" {
			found = true
		}
	}
	if !found {
		t.Error("Expected error-level wildcard-resource issue for *")
	}
}

func TestAnalyzeResourceWithInternalWildcard(t *testing.T) {
	// arn:aws:s3:::bucket* (no trailing /) is suspicious
	doc := makePolicy(
		stmt([]string{"s3:GetObject"}, "arn:aws:s3:::bucket*"),
	)

	result := Analyze(doc)

	found := false
	for _, issue := range result.Issues {
		if issue.Type == "wildcard-resource" && issue.Severity == "warning" {
			found = true
		}
	}
	if !found {
		t.Error("Expected warning for resource with non-trailing wildcard")
	}
}

func TestAnalyzeResourceWithTrailingSlashWildcard(t *testing.T) {
	// arn:aws:s3:::bucket/* is normal and should NOT trigger wildcard-resource warning
	doc := makePolicy(
		stmt([]string{"s3:GetObject"}, "arn:aws:s3:::my-bucket/*"),
	)

	result := Analyze(doc)
	for _, issue := range result.Issues {
		if issue.Type == "wildcard-resource" {
			t.Errorf("Should NOT flag trailing /* resource, got: %+v", issue)
		}
	}
}

func TestAnalyzeDangerousPermissions(t *testing.T) {
	dangerous := []string{
		"iam:CreateUser",
		"iam:AttachUserPolicy",
		"iam:CreateAccessKey",
		"sts:AssumeRole",
	}

	for _, action := range dangerous {
		t.Run(action, func(t *testing.T) {
			doc := makePolicy(
				stmt([]string{action}, "*"),
			)

			result := Analyze(doc)
			found := false
			for _, issue := range result.Issues {
				if issue.Type == "dangerous-permission" && strings.Contains(issue.Message, action) {
					found = true
				}
			}
			if !found {
				t.Errorf("Expected dangerous-permission issue for %s", action)
			}
		})
	}
}

func TestAnalyzeAdminAccess(t *testing.T) {
	adminActions := []string{"*:*"}

	for _, action := range adminActions {
		t.Run(action, func(t *testing.T) {
			doc := makePolicy(
				stmt([]string{action}, "*"),
			)

			result := Analyze(doc)
			found := false
			for _, issue := range result.Issues {
				if issue.Type == "admin-access" && issue.Severity == "error" {
					found = true
				}
			}
			if !found {
				t.Errorf("Expected admin-access error issue for %s", action)
			}
		})
	}
}

func TestAnalyzeMultipleStatements(t *testing.T) {
	doc := makePolicy(
		stmt([]string{"s3:GetObject"}, "arn:aws:s3:::bucket/*"),
		stmt([]string{"*"}, "*"),
		stmt([]string{"iam:CreateUser"}, "arn:aws:iam::123456:user/*"),
	)

	result := Analyze(doc)
	if result.Summary.TotalStatements != 3 {
		t.Errorf("TotalStatements = %d, want 3", result.Summary.TotalStatements)
	}
	if result.Summary.IssueCount == 0 {
		t.Error("Expected issues for policy with wildcards and dangerous permissions")
	}
}

func TestAnalyzeEmptyPolicy(t *testing.T) {
	doc := makePolicy()

	result := Analyze(doc)
	if result.Summary.TotalStatements != 0 {
		t.Errorf("TotalStatements = %d, want 0", result.Summary.TotalStatements)
	}
	if len(result.Issues) != 0 {
		t.Errorf("Expected 0 issues for empty policy, got %d", len(result.Issues))
	}
}

func TestGenerateSuggestions(t *testing.T) {
	result := &AnalysisResult{
		Issues: []Issue{{Type: "wildcard-action"}},
		Summary: AnalysisSummary{
			WildcardActions:   2,
			WildcardResources: 1,
			OverlyBroad:       1,
		},
	}

	suggestions := generateSuggestions(result)

	if len(suggestions) != 3 {
		t.Fatalf("Expected 3 suggestions, got %d: %v", len(suggestions), suggestions)
	}

	hasWildcardAction := false
	hasWildcardResource := false
	hasRunSuggestion := false
	for _, s := range suggestions {
		if strings.Contains(s, "wildcard action") {
			hasWildcardAction = true
		}
		if strings.Contains(s, "wildcard resource") {
			hasWildcardResource = true
		}
		if strings.Contains(s, "iampg run") {
			hasRunSuggestion = true
		}
	}
	if !hasWildcardAction {
		t.Error("Missing wildcard action suggestion")
	}
	if !hasWildcardResource {
		t.Error("Missing wildcard resource suggestion")
	}
	if !hasRunSuggestion {
		t.Error("Missing 'iampg run' suggestion")
	}
}

func TestFormatResultContainsIssues(t *testing.T) {
	result := &AnalysisResult{
		Issues: []Issue{
			{Severity: "error", Type: "wildcard-action", Message: "grants all actions", Suggestion: "be specific"},
			{Severity: "warning", Type: "dangerous-permission", Message: "iam:CreateUser"},
		},
		Summary: AnalysisSummary{
			TotalStatements: 2,
			IssueCount:      2,
		},
		Suggestions: []string{"Fix wildcards"},
	}

	output := FormatResult(result)

	checks := []string{
		"Policy Analysis",
		"Statements: 2",
		"Issues: 2",
		"wildcard-action",
		"dangerous-permission",
		"grants all actions",
		"Fix wildcards",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("FormatResult output missing %q", check)
		}
	}
}
