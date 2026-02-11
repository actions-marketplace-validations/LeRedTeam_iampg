package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/LeRedTeam/iampg/parse"
	"github.com/LeRedTeam/iampg/policy"
	"github.com/spf13/cobra"
)

var parseCloudtrail string
var parseError string
var parseStdin bool
var parseOutput string
var parseFormat string
var parseResourceName string

var parseCmd = &cobra.Command{
	Use:   "parse",
	Short: "Parse CloudTrail logs or AccessDenied errors to generate IAM policy",
	Long: `Parse existing AWS logs or error messages to generate IAM policies.

Formats:
  json       JSON policy document (free)
  yaml       YAML policy document (pro)
  terraform  Terraform aws_iam_policy resource (pro)
  sarif      SARIF report for CI integration (pro)

Examples:
  iampg parse --cloudtrail trail.json
  iampg parse --error "User: arn:aws:iam::123:user/dev is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key"
  iampg parse --cloudtrail trail.json --format terraform
  cat errors.txt | iampg parse --stdin`,
	RunE: runParse,
}

func init() {
	rootCmd.AddCommand(parseCmd)
	parseCmd.Flags().StringVar(&parseCloudtrail, "cloudtrail", "", "CloudTrail JSON log file")
	parseCmd.Flags().StringVar(&parseError, "error", "", "AccessDenied error message")
	parseCmd.Flags().BoolVar(&parseStdin, "stdin", false, "Read input from stdin")
	parseCmd.Flags().StringVarP(&parseOutput, "output", "o", "", "Write policy to file (default: stdout)")
	parseCmd.Flags().StringVarP(&parseFormat, "format", "f", "json", "Output format: json, yaml, terraform, sarif")
	parseCmd.Flags().StringVar(&parseResourceName, "resource-name", "generated_policy", "Terraform resource name")
}

func runParse(cmd *cobra.Command, args []string) error {
	if parseCloudtrail == "" && parseError == "" && !parseStdin {
		return fmt.Errorf("must specify --cloudtrail, --error, or --stdin")
	}

	var calls []policy.ObservedCall

	// Parse CloudTrail file
	if parseCloudtrail != "" {
		data, err := os.ReadFile(parseCloudtrail)
		if err != nil {
			return fmt.Errorf("failed to read CloudTrail file: %w", err)
		}

		parsed, err := parse.ParseCloudTrail(data)
		if err != nil {
			return fmt.Errorf("failed to parse CloudTrail: %w", err)
		}
		calls = append(calls, parsed...)
		fmt.Fprintf(os.Stderr, "Parsed %d events from CloudTrail.\n", len(parsed))
	}

	// Parse error message
	if parseError != "" {
		parsed := parse.ParseAccessDenied(parseError)
		calls = append(calls, parsed...)
		if len(parsed) == 0 {
			fmt.Fprintln(os.Stderr, "Warning: Could not parse any permissions from error message.")
		} else {
			fmt.Fprintf(os.Stderr, "Parsed %d permission(s) from error.\n", len(parsed))
		}
	}

	// Parse stdin
	if parseStdin {
		input, err := readStdin()
		if err != nil {
			return fmt.Errorf("failed to read stdin: %w", err)
		}

		// Try CloudTrail format first
		if strings.Contains(input, "eventSource") || strings.HasPrefix(strings.TrimSpace(input), "{") || strings.HasPrefix(strings.TrimSpace(input), "[") {
			parsed, err := parse.ParseCloudTrail([]byte(input))
			if err == nil && len(parsed) > 0 {
				calls = append(calls, parsed...)
				fmt.Fprintf(os.Stderr, "Parsed %d events from CloudTrail (stdin).\n", len(parsed))
			} else {
				// Fall back to error parsing
				parsed := parse.ParseMultipleErrors(input)
				calls = append(calls, parsed...)
				fmt.Fprintf(os.Stderr, "Parsed %d permission(s) from errors (stdin).\n", len(parsed))
			}
		} else {
			// Parse as error messages
			parsed := parse.ParseMultipleErrors(input)
			calls = append(calls, parsed...)
			fmt.Fprintf(os.Stderr, "Parsed %d permission(s) from errors (stdin).\n", len(parsed))
		}
	}

	// Generate policy
	doc := policy.Generate(calls)

	// Output the policy
	if err := outputPolicy(doc, parseFormat, parseOutput, parseResourceName); err != nil {
		return err
	}

	if len(calls) == 0 {
		fmt.Fprintln(os.Stderr, "No permissions found in input.")
	}

	return nil
}

func readStdin() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	var builder strings.Builder

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				builder.WriteString(line)
				break
			}
			return "", err
		}
		builder.WriteString(line)
	}

	return builder.String(), nil
}
