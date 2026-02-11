package cmd

import (
	"fmt"
	"os"

	"github.com/LeRedTeam/iampg/capture"
	"github.com/LeRedTeam/iampg/policy"
	"github.com/spf13/cobra"
)

var runOutput string
var runFormat string
var runVerbose bool
var runResourceName string

var runCmd = &cobra.Command{
	Use:   "run -- <command>",
	Short: "Capture AWS calls from a command and generate IAM policy",
	Long: `Execute a command while capturing AWS API calls made during execution.
Generates a minimal IAM policy granting only the observed permissions.

Formats:
  json       JSON policy document (free)
  yaml       YAML policy document (pro)
  terraform  Terraform aws_iam_policy resource (pro)
  sarif      SARIF report for CI integration (pro)

Example:
  iampg run -- aws s3 ls
  iampg run -- aws s3 cp file.txt s3://bucket/
  iampg run --format terraform -- terraform apply
  iampg run -v -- python deploy.py`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.MinimumNArgs(1),
	RunE:                  runRun,
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&runOutput, "output", "o", "", "Write policy to file (default: stdout)")
	runCmd.Flags().StringVarP(&runFormat, "format", "f", "json", "Output format: json, yaml, terraform, sarif")
	runCmd.Flags().BoolVarP(&runVerbose, "verbose", "v", false, "Show captured AWS calls")
	runCmd.Flags().StringVar(&runResourceName, "resource-name", "generated_policy", "Terraform resource name")
}

func runRun(cmd *cobra.Command, args []string) error {
	runner := capture.NewRunner(runVerbose)

	// Run the command and capture calls
	calls, exitCode, err := runner.RunWithCloudTrailSim(args)
	if err != nil {
		return fmt.Errorf("failed to run command: %w", err)
	}

	// Generate policy from observed calls
	doc := policy.Generate(calls)

	// Output the policy
	if err := outputPolicy(doc, runFormat, runOutput, runResourceName); err != nil {
		return err
	}

	// Report on captured calls
	if len(calls) == 0 {
		fmt.Fprintln(os.Stderr, "No AWS API calls detected.")
	} else {
		fmt.Fprintf(os.Stderr, "Captured %d AWS API call(s).\n", len(calls))
	}

	// Exit with the wrapped command's exit code if it failed
	if exitCode != 0 {
		fmt.Fprintf(os.Stderr, "Command exited with code %d. Policy generated from observed calls.\n", exitCode)
		os.Exit(exitCode)
	}

	return nil
}
