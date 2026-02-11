package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/LeRedTeam/iampg/license"
	"github.com/LeRedTeam/iampg/refine"
	"github.com/spf13/cobra"
)

var refineInput string
var refineCompare string
var refineFormat string
var refineEnforce bool

var refineCmd = &cobra.Command{
	Use:   "refine",
	Short: "Analyze and improve IAM policies (pro)",
	Long: `Analyze IAM policies for security issues and suggest improvements.

Features:
  - Wildcard detection
  - Scoping suggestions
  - Dangerous permission detection
  - Policy comparison/diff

Examples:
  iampg refine --input policy.json
  iampg refine --input policy.json --format json
  iampg refine --input current.json --compare baseline.json
  iampg refine --input policy.json --enforce`,
	RunE: runRefine,
}

func init() {
	rootCmd.AddCommand(refineCmd)
	refineCmd.Flags().StringVarP(&refineInput, "input", "i", "", "Input policy JSON file (required)")
	refineCmd.Flags().StringVar(&refineCompare, "compare", "", "Baseline policy to compare against")
	refineCmd.Flags().StringVarP(&refineFormat, "format", "f", "text", "Output format: text, json")
	refineCmd.Flags().BoolVar(&refineEnforce, "enforce", false, "Exit with error if issues found (for CI)")
	refineCmd.MarkFlagRequired("input")
}

func runRefine(cmd *cobra.Command, args []string) error {
	// Check license
	if err := license.RequireFeature("refine"); err != nil {
		return err
	}

	// Load input policy
	doc, err := refine.LoadPolicy(refineInput)
	if err != nil {
		return err
	}

	// If comparing, load baseline and diff
	if refineCompare != "" {
		if err := license.RequireFeature("diff"); err != nil {
			return err
		}

		baseline, err := refine.LoadPolicy(refineCompare)
		if err != nil {
			return fmt.Errorf("failed to load baseline: %w", err)
		}

		diffResult := refine.Diff(baseline, doc)

		if refineFormat == "json" {
			output, _ := json.MarshalIndent(diffResult, "", "  ")
			fmt.Println(string(output))
		} else {
			fmt.Print(refine.FormatDiff(diffResult))
		}

		if refineEnforce && diffResult.HasDrift() {
			fmt.Fprintln(os.Stderr, "Policy drift detected.")
			os.Exit(1)
		}

		return nil
	}

	// Analyze policy
	result := refine.Analyze(doc)

	if refineFormat == "json" {
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
	} else {
		fmt.Print(refine.FormatResult(result))
	}

	// Enforce mode: exit with error if issues found
	if refineEnforce && result.Summary.OverlyBroad > 0 {
		fmt.Fprintln(os.Stderr, "Policy contains overly broad permissions.")
		os.Exit(1)
	}

	return nil
}
