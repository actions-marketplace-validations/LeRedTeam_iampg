package cmd

import (
	"fmt"
	"os"

	"github.com/LeRedTeam/iampg/license"
	"github.com/LeRedTeam/iampg/policy"
)

// outputPolicy formats and outputs a policy document.
func outputPolicy(doc *policy.Document, format, outputPath, resourceName string) error {
	// Check license for paid formats
	paidFormats := map[string]string{
		"yaml":      "yaml",
		"terraform": "terraform",
		"sarif":     "sarif",
	}

	if feature, isPaid := paidFormats[format]; isPaid {
		if err := license.RequireFeature(feature); err != nil {
			return err
		}
	}

	// Format the output
	options := map[string]string{
		"resource_name": resourceName,
		"version":       version,
	}

	output, err := doc.Format(policy.Format(format), options)
	if err != nil {
		return fmt.Errorf("failed to format policy: %w", err)
	}

	// Write output
	if outputPath != "" {
		if err := os.WriteFile(outputPath, output, 0644); err != nil {
			return fmt.Errorf("failed to write to %s: %w", outputPath, err)
		}
		fmt.Fprintf(os.Stderr, "Policy written to %s\n", outputPath)
	} else {
		fmt.Println(string(output))
	}

	return nil
}
