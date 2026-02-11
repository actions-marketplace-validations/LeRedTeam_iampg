package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/LeRedTeam/iampg/license"
	"github.com/LeRedTeam/iampg/policy"
	"github.com/spf13/cobra"
)

var aggregateFiles []string
var aggregateOutput string
var aggregateFormat string
var aggregateResourceName string

var aggregateCmd = &cobra.Command{
	Use:   "aggregate",
	Short: "Combine multiple policies into one (pro)",
	Long: `Aggregate multiple policy files into a single merged policy.

Useful for combining policies from multiple test runs or environments.

Examples:
  iampg aggregate --files policy1.json,policy2.json
  iampg aggregate --files policy1.json --files policy2.json --output combined.json
  iampg aggregate --files "*.json" --format terraform`,
	RunE: runAggregate,
}

func init() {
	rootCmd.AddCommand(aggregateCmd)
	aggregateCmd.Flags().StringSliceVarP(&aggregateFiles, "files", "f", []string{}, "Policy files to aggregate (required)")
	aggregateCmd.Flags().StringVarP(&aggregateOutput, "output", "o", "", "Output file (default: stdout)")
	aggregateCmd.Flags().StringVar(&aggregateFormat, "format", "json", "Output format: json, yaml, terraform")
	aggregateCmd.Flags().StringVar(&aggregateResourceName, "resource-name", "aggregated_policy", "Terraform resource name")
	aggregateCmd.MarkFlagRequired("files")
}

func runAggregate(cmd *cobra.Command, args []string) error {
	// Check license
	if err := license.RequireFeature("aggregate"); err != nil {
		return err
	}

	if len(aggregateFiles) == 0 {
		return fmt.Errorf("at least one policy file is required")
	}

	// Load and merge all policies
	var allCalls []policy.ObservedCall

	for _, file := range aggregateFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", file, err)
		}

		var doc policy.Document
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("failed to parse %s: %w", file, err)
		}

		// Convert statements back to observed calls
		for _, stmt := range doc.Statement {
			for _, action := range stmt.Action {
				parts := splitAction(action)
				allCalls = append(allCalls, policy.ObservedCall{
					Service:  parts[0],
					Action:   parts[1],
					Resource: stmt.Resource,
				})
			}
		}

		fmt.Fprintf(os.Stderr, "Loaded %d statements from %s\n", len(doc.Statement), file)
	}

	// Generate merged policy
	merged := policy.Generate(allCalls)

	// Output
	if err := outputPolicy(merged, aggregateFormat, aggregateOutput, aggregateResourceName); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Aggregated %d files into %d statements.\n", len(aggregateFiles), len(merged.Statement))

	return nil
}

func splitAction(action string) [2]string {
	for i, c := range action {
		if c == ':' {
			return [2]string{action[:i], action[i+1:]}
		}
	}
	return [2]string{"", action}
}
