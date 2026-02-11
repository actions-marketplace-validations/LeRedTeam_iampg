package capture

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/LeRedTeam/iampg/policy"
)

// Runner executes a command and captures AWS API calls.
type Runner struct {
	capturer *Capturer
	verbose  bool
}

// NewRunner creates a new Runner.
func NewRunner(verbose bool) *Runner {
	return &Runner{
		capturer: New(),
		verbose:  verbose,
	}
}

// Run executes the command and returns observed calls and the exit code.
func (r *Runner) Run(args []string) ([]policy.ObservedCall, int, error) {
	if len(args) == 0 {
		return nil, 1, fmt.Errorf("no command provided")
	}

	cmd := exec.Command(args[0], args[1:]...)

	// Set up environment with AWS debug logging
	cmd.Env = append(os.Environ(),
		"AWS_DEBUG=true",
	)

	// Capture stderr for debug output
	var stderrBuf bytes.Buffer
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, 1, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Pass through stdout
	cmd.Stdout = os.Stdout

	if err := cmd.Start(); err != nil {
		return nil, 1, fmt.Errorf("failed to start command: %w", err)
	}

	// Read stderr and parse for AWS calls
	go func() {
		reader := bufio.NewReader(stderrPipe)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					stderrBuf.WriteString(line)
				}
				break
			}

			// Parse AWS debug output
			if call := r.parseDebugLine(line); call != nil {
				r.capturer.AddCall(*call)
				if r.verbose {
					fmt.Fprintf(os.Stderr, "[capture] %s:%s on %s\n", call.Service, call.Action, call.Resource)
				}
			} else {
				// Pass through non-capture stderr
				fmt.Fprint(os.Stderr, line)
			}
		}
	}()

	err = cmd.Wait()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, 1, fmt.Errorf("command failed: %w", err)
		}
	}

	return r.capturer.Calls(), exitCode, nil
}

// AWS CLI debug output patterns
var (
	// Pattern: "2024-01-01 12:00:00,000 - MainThread - botocore.endpoint - DEBUG - Making request for OperationName"
	botocoreOpPattern = regexp.MustCompile(`Making request for (\w+)`)
	// Pattern: "2024-01-01 12:00:00,000 - MainThread - botocore.endpoint - DEBUG - https://service.region.amazonaws.com/"
	botocoreURLPattern = regexp.MustCompile(`https://([a-z0-9-]+)\.([a-z0-9-]+)\.amazonaws\.com`)
	// AWS CLI v2 pattern: "AWS CLI command entered with arguments: [...]"
	awscliPattern = regexp.MustCompile(`aws\s+([a-z0-9-]+)\s+([a-z0-9-]+)`)
)

func (r *Runner) parseDebugLine(line string) *policy.ObservedCall {
	// Try to extract operation name
	if matches := botocoreOpPattern.FindStringSubmatch(line); matches != nil {
		return &policy.ObservedCall{
			Action: matches[1],
		}
	}

	// Try to extract service and region from URL
	if matches := botocoreURLPattern.FindStringSubmatch(line); matches != nil {
		service := matches[1]
		region := matches[2]

		// Update the last incomplete call with service info
		calls := r.capturer.Calls()
		if len(calls) > 0 {
			lastCall := &calls[len(calls)-1]
			if lastCall.Service == "" {
				lastCall.Service = service
				lastCall.Region = region
			}
		}
	}

	return nil
}

// RunWithProxy executes with an HTTP proxy (for non-TLS or with MITM).
func (r *Runner) RunWithProxy(args []string) ([]policy.ObservedCall, int, error) {
	proxy := NewProxy(r.capturer, r.verbose)
	addr, err := proxy.Start()
	if err != nil {
		return nil, 1, fmt.Errorf("failed to start proxy: %w", err)
	}
	defer proxy.Stop()

	if len(args) == 0 {
		return nil, 1, fmt.Errorf("no command provided")
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(),
		"HTTP_PROXY=http://"+addr,
		"HTTPS_PROXY=http://"+addr,
		"http_proxy=http://"+addr,
		"https_proxy=http://"+addr,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}

	return r.capturer.Calls(), exitCode, nil
}

// RunWithCloudTrailSim simulates by parsing AWS CLI commands directly.
// This is the most reliable method for AWS CLI.
func (r *Runner) RunWithCloudTrailSim(args []string) ([]policy.ObservedCall, int, error) {
	// Check if this is an AWS CLI command
	if len(args) > 0 && (args[0] == "aws" || strings.HasSuffix(args[0], "/aws")) {
		call := parseAWSCLIArgs(args)
		if call != nil {
			r.capturer.AddCall(*call)
			if r.verbose {
				fmt.Fprintf(os.Stderr, "[capture] %s:%s on %s\n", call.Service, call.Action, call.Resource)
			}
		}
	}

	// Still run the command
	if len(args) == 0 {
		return nil, 1, fmt.Errorf("no command provided")
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}

	return r.capturer.Calls(), exitCode, nil
}

// parseAWSCLIArgs parses AWS CLI arguments to determine the API call.
func parseAWSCLIArgs(args []string) *policy.ObservedCall {
	if len(args) < 3 {
		return nil
	}

	// Skip 'aws' and find service and command
	var service, command string
	var positionalArgs []string

	i := 1
	for i < len(args) {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			// Skip flag and its value if not boolean
			i++
			if i < len(args) && !strings.HasPrefix(args[i], "--") {
				i++
			}
			continue
		}
		if service == "" {
			service = arg
		} else if command == "" {
			command = arg
		} else {
			positionalArgs = append(positionalArgs, arg)
		}
		i++
	}

	if service == "" || command == "" {
		return nil
	}

	// Extract resource from arguments
	resource := extractResourceFromArgs(service, command, args)

	// Map CLI command to IAM action
	action := cliCommandToAction(service, command)

	// Special case: s3 ls - depends on whether bucket is specified
	if service == "s3" && command == "ls" {
		hasS3Path := false
		for _, arg := range args {
			if strings.HasPrefix(arg, "s3://") {
				hasS3Path = true
				break
			}
		}
		if hasS3Path {
			action = "ListBucket"
		} else {
			action = "ListAllMyBuckets"
			resource = "*"
		}
	}

	return &policy.ObservedCall{
		Service:  service,
		Action:   action,
		Resource: resource,
	}
}

// cliCommandToAction maps AWS CLI commands to IAM actions.
// For S3 ls, we need args to determine if it's ListAllMyBuckets or ListBucket
func cliCommandToAction(service, command string) string {
	// Special mappings for services where CLI commands don't match IAM actions
	// Note: s3 ls is handled specially in parseAWSCLIArgs
	s3Actions := map[string]string{
		"cp":      "PutObject", // Could be GetObject too, determined by direction
		"mv":      "PutObject",
		"rm":      "DeleteObject",
		"mb":      "CreateBucket",
		"rb":      "DeleteBucket",
		"sync":    "PutObject",
		"presign": "GetObject",
		"website": "PutBucketWebsite",
	}

	if service == "s3" {
		if action, ok := s3Actions[command]; ok {
			return action
		}
	}

	// Convert kebab-case to PascalCase for standard mappings
	parts := strings.Split(command, "-")
	var result strings.Builder
	for _, p := range parts {
		if len(p) > 0 {
			result.WriteString(strings.ToUpper(p[:1]))
			if len(p) > 1 {
				result.WriteString(p[1:])
			}
		}
	}
	return result.String()
}

// extractResourceFromArgs extracts resource ARN from CLI arguments.
func extractResourceFromArgs(service, command string, args []string) string {
	switch service {
	case "s3":
		return extractS3Resource(args)
	case "dynamodb":
		return extractDynamoDBResource(args)
	case "lambda":
		return extractLambdaResource(args)
	case "sqs":
		return extractSQSResource(args)
	default:
		return "*"
	}
}

func extractS3Resource(args []string) string {
	var s3Paths []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "s3://") {
			s3Paths = append(s3Paths, arg)
		}
	}

	if len(s3Paths) == 0 {
		return "arn:aws:s3:::*"
	}

	// Parse first S3 path (for ls, this is the target)
	path := strings.TrimPrefix(s3Paths[0], "s3://")
	path = strings.TrimSuffix(path, "/")
	parts := strings.SplitN(path, "/", 2)
	bucket := parts[0]

	if bucket == "" {
		return "arn:aws:s3:::*"
	}
	if len(parts) > 1 && parts[1] != "" {
		return "arn:aws:s3:::" + bucket + "/" + parts[1]
	}
	// For bucket-level operations, need both bucket and bucket/* resources
	return "arn:aws:s3:::" + bucket + "/*"
}

func extractDynamoDBResource(args []string) string {
	for i, arg := range args {
		if arg == "--table-name" && i+1 < len(args) {
			return "arn:aws:dynamodb:*:*:table/" + args[i+1]
		}
	}
	return "*"
}

func extractLambdaResource(args []string) string {
	for i, arg := range args {
		if arg == "--function-name" && i+1 < len(args) {
			return "arn:aws:lambda:*:*:function:" + args[i+1]
		}
	}
	return "*"
}

func extractSQSResource(args []string) string {
	for i, arg := range args {
		if arg == "--queue-url" && i+1 < len(args) {
			// Parse queue URL to ARN
			url := args[i+1]
			// URL format: https://sqs.region.amazonaws.com/account/queue-name
			parts := strings.Split(url, "/")
			if len(parts) >= 5 {
				return "arn:aws:sqs:*:" + parts[3] + ":" + parts[4]
			}
		}
	}
	return "*"
}
