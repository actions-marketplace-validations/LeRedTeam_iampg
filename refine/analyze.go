package refine

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/LeRedTeam/iampg/policy"
)

// Issue represents a policy issue found during analysis.
type Issue struct {
	Severity    string `json:"severity"` // error, warning, info
	Type        string `json:"type"`
	Message     string `json:"message"`
	Suggestion  string `json:"suggestion,omitempty"`
	StatementID int    `json:"statement_id,omitempty"`
}

// AnalysisResult contains the results of policy analysis.
type AnalysisResult struct {
	Issues      []Issue          `json:"issues"`
	Summary     AnalysisSummary  `json:"summary"`
	Suggestions []string         `json:"suggestions,omitempty"`
}

// AnalysisSummary provides a summary of the analysis.
type AnalysisSummary struct {
	TotalStatements  int `json:"total_statements"`
	WildcardActions  int `json:"wildcard_actions"`
	WildcardResources int `json:"wildcard_resources"`
	OverlyBroad      int `json:"overly_broad"`
	IssueCount       int `json:"issue_count"`
}

// LoadPolicy loads a policy from a file.
func LoadPolicy(path string) (*policy.Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var doc policy.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse policy JSON: %w", err)
	}

	return &doc, nil
}

// Analyze performs analysis on a policy document.
func Analyze(doc *policy.Document) *AnalysisResult {
	result := &AnalysisResult{
		Issues: []Issue{},
	}

	for i, stmt := range doc.Statement {
		// Check for wildcard actions
		for _, action := range stmt.Action {
			if action == "*" {
				result.Issues = append(result.Issues, Issue{
					Severity:    "error",
					Type:        "wildcard-action",
					Message:     "Statement grants all actions (*)",
					Suggestion:  "Replace with specific actions required by your application",
					StatementID: i,
				})
				result.Summary.WildcardActions++
				result.Summary.OverlyBroad++
			} else if strings.HasSuffix(action, ":*") {
				result.Issues = append(result.Issues, Issue{
					Severity:    "warning",
					Type:        "wildcard-action",
					Message:     fmt.Sprintf("Statement grants all actions for service: %s", action),
					Suggestion:  fmt.Sprintf("Replace %s with specific actions", action),
					StatementID: i,
				})
				result.Summary.WildcardActions++
			} else if strings.Contains(action, "*") {
				result.Issues = append(result.Issues, Issue{
					Severity:    "info",
					Type:        "wildcard-action",
					Message:     fmt.Sprintf("Action contains wildcard: %s", action),
					Suggestion:  "Consider if wildcard is necessary",
					StatementID: i,
				})
			}
		}

		// Check for wildcard resources
		if stmt.Resource == "*" {
			result.Issues = append(result.Issues, Issue{
				Severity:    "error",
				Type:        "wildcard-resource",
				Message:     "Statement applies to all resources (*)",
				Suggestion:  "Scope to specific resource ARNs",
				StatementID: i,
			})
			result.Summary.WildcardResources++
			result.Summary.OverlyBroad++
		} else if strings.Contains(stmt.Resource, "*") && !strings.HasSuffix(stmt.Resource, "/*") {
			result.Issues = append(result.Issues, Issue{
				Severity:    "warning",
				Type:        "wildcard-resource",
				Message:     fmt.Sprintf("Resource contains wildcard: %s", stmt.Resource),
				Suggestion:  "Consider scoping to more specific resources",
				StatementID: i,
			})
		}

		// Check for overly permissive patterns
		checkOverlyPermissive(stmt, i, result)
	}

	result.Summary.TotalStatements = len(doc.Statement)
	result.Summary.IssueCount = len(result.Issues)

	// Generate suggestions
	result.Suggestions = generateSuggestions(result)

	return result
}

func checkOverlyPermissive(stmt policy.Statement, idx int, result *AnalysisResult) {
	// Check for dangerous action patterns
	dangerousPatterns := map[string]string{
		"iam:*":             "Full IAM access is extremely dangerous",
		"iam:CreateUser":    "Can create new IAM users",
		"iam:AttachUserPolicy": "Can attach policies to users",
		"iam:CreateAccessKey": "Can create access keys for any user",
		"sts:AssumeRole":    "Can assume other roles - verify trust policy",
		"s3:*":              "Full S3 access to specified resources",
		"ec2:*":             "Full EC2 access to specified resources",
		"lambda:*":          "Full Lambda access to specified resources",
	}

	for _, action := range stmt.Action {
		if msg, found := dangerousPatterns[action]; found {
			result.Issues = append(result.Issues, Issue{
				Severity:    "warning",
				Type:        "dangerous-permission",
				Message:     fmt.Sprintf("Potentially dangerous permission: %s", action),
				Suggestion:  msg,
				StatementID: idx,
			})
		}
	}

	// Check for admin-like permissions
	adminPatterns := []string{"*:*", "AdministratorAccess"}
	for _, action := range stmt.Action {
		for _, pattern := range adminPatterns {
			if action == pattern {
				result.Issues = append(result.Issues, Issue{
					Severity:    "error",
					Type:        "admin-access",
					Message:     "Statement grants administrator-level access",
					Suggestion:  "Replace with least-privilege permissions",
					StatementID: idx,
				})
				result.Summary.OverlyBroad++
			}
		}
	}
}

func generateSuggestions(result *AnalysisResult) []string {
	var suggestions []string

	if result.Summary.WildcardActions > 0 {
		suggestions = append(suggestions,
			fmt.Sprintf("Replace %d wildcard action(s) with specific actions", result.Summary.WildcardActions))
	}

	if result.Summary.WildcardResources > 0 {
		suggestions = append(suggestions,
			fmt.Sprintf("Scope %d wildcard resource(s) to specific ARNs", result.Summary.WildcardResources))
	}

	if result.Summary.OverlyBroad > 0 {
		suggestions = append(suggestions,
			"Run 'iampg run' to capture actual permissions needed")
	}

	if len(result.Issues) == 0 {
		suggestions = append(suggestions, "Policy follows least-privilege principles")
	}

	return suggestions
}

// FormatResult formats the analysis result as a string.
func FormatResult(result *AnalysisResult) string {
	var sb strings.Builder

	sb.WriteString("Policy Analysis\n")
	sb.WriteString("===============\n\n")

	sb.WriteString(fmt.Sprintf("Statements: %d\n", result.Summary.TotalStatements))
	sb.WriteString(fmt.Sprintf("Issues: %d\n\n", result.Summary.IssueCount))

	if len(result.Issues) > 0 {
		sb.WriteString("Issues Found:\n")
		for _, issue := range result.Issues {
			icon := "ℹ️"
			switch issue.Severity {
			case "error":
				icon = "❌"
			case "warning":
				icon = "⚠️"
			}
			sb.WriteString(fmt.Sprintf("  %s [%s] %s\n", icon, issue.Type, issue.Message))
			if issue.Suggestion != "" {
				sb.WriteString(fmt.Sprintf("     → %s\n", issue.Suggestion))
			}
		}
		sb.WriteString("\n")
	}

	if len(result.Suggestions) > 0 {
		sb.WriteString("Suggestions:\n")
		for _, s := range result.Suggestions {
			sb.WriteString(fmt.Sprintf("  • %s\n", s))
		}
	}

	return sb.String()
}
