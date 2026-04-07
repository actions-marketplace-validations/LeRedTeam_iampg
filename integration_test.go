// Copyright (C) 2026 LeRedTeam
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// --- Test infrastructure ---

// buildBinary builds the iampg binary with default (production) public key.
func buildBinary(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	binary := filepath.Join(tmpDir, "iampg")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to build binary: %v", err)
	}
	return binary
}

// buildBinaryWithKey builds the binary with a custom public key for license testing.
func buildBinaryWithKey(t *testing.T, publicKeyBase64 string) string {
	t.Helper()
	tmpDir := t.TempDir()
	binary := filepath.Join(tmpDir, "iampg")
	ldflags := "-X github.com/LeRedTeam/iampg/license.publicKeyBase64=" + publicKeyBase64
	cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", binary, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to build binary with custom key: %v", err)
	}
	return binary
}

// generateTestKeypair generates an Ed25519 keypair for testing.
func generateTestKeypair(t *testing.T) (pubBase64, privBase64 string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(pub),
		base64.RawURLEncoding.EncodeToString(priv)
}

// generateLicenseKey uses the binary to generate a license key.
func generateLicenseKey(t *testing.T, binary, privKey, email, tier string, days int) string {
	t.Helper()
	cmd := exec.Command(binary, "license", "generate",
		"--email", email,
		"--tier", tier,
		"--days", strconv.Itoa(days),
		"--private-key", privKey)
	output, err := cmd.Output()
	if err != nil {
		// Try combined output for error details
		cmd2 := exec.Command(binary, "license", "generate",
			"--email", email, "--tier", tier, "--days", strconv.Itoa(days),
			"--private-key", privKey)
		combined, _ := cmd2.CombinedOutput()
		t.Fatalf("license generate failed: %v\nOutput: %s", err, combined)
	}
	return strings.TrimSpace(string(output))
}

// writeTempFile creates a temporary file with the given content.
func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// samplePolicy returns a minimal valid IAM policy JSON.
func samplePolicy() string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::my-bucket/*"}]}`
}

// wildcardPolicy returns a policy with security issues.
func wildcardPolicy() string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":"*"}]}`
}

// parseJSONPolicy parses a JSON policy from bytes, failing the test if invalid.
func parseJSONPolicy(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v\nContent: %s", err, string(data))
	}
	return doc
}

// --- Run command tests ---

func TestIntegration_RunEcho(t *testing.T) {
	binary := buildBinary(t)
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "policy.json")

	cmd := exec.Command(binary, "run", "--output", outputFile, "--", "echo", "hello")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("iampg run failed: %v", err)
	}

	data, _ := os.ReadFile(outputFile)
	doc := parseJSONPolicy(t, data)

	if doc["Version"] != "2012-10-17" {
		t.Errorf("Version = %v, want 2012-10-17", doc["Version"])
	}
	stmts := doc["Statement"].([]any)
	if len(stmts) != 0 {
		t.Errorf("expected 0 statements for non-AWS command, got %d", len(stmts))
	}
}

func TestIntegration_RunS3Ls(t *testing.T) {
	binary := buildBinary(t)
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "policy.json")

	// aws command will fail (no creds) but policy should still be generated
	cmd := exec.Command(binary, "run", "--output", outputFile, "--", "aws", "s3", "ls", "s3://test-bucket/")
	cmd.Run() // ignore exit code

	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("no output file: %v", err)
	}

	doc := parseJSONPolicy(t, data)
	stmts := doc["Statement"].([]any)
	if len(stmts) == 0 {
		t.Fatal("expected statements")
	}

	actions := stmts[0].(map[string]any)["Action"].([]any)
	found := false
	for _, a := range actions {
		if a.(string) == "s3:ListBucket" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected s3:ListBucket, got %v", actions)
	}
}

func TestIntegration_RunS3Cp(t *testing.T) {
	binary := buildBinary(t)
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "policy.json")

	cmd := exec.Command(binary, "run", "--output", outputFile, "--", "aws", "s3", "cp", "file.txt", "s3://my-bucket/uploads/file.txt")
	cmd.Run()

	data, _ := os.ReadFile(outputFile)
	doc := parseJSONPolicy(t, data)
	stmts := doc["Statement"].([]any)
	if len(stmts) == 0 {
		t.Fatal("expected statements")
	}

	stmt := stmts[0].(map[string]any)
	resource := stmt["Resource"].(string)
	if !strings.Contains(resource, "my-bucket") {
		t.Errorf("Resource = %q, should contain my-bucket", resource)
	}
}

func TestIntegration_RunDynamoDB(t *testing.T) {
	binary := buildBinary(t)
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "policy.json")

	cmd := exec.Command(binary, "run", "--output", outputFile, "--",
		"aws", "dynamodb", "get-item", "--table-name", "Users", "--key", `{"id":{"S":"123"}}`)
	cmd.Run()

	data, _ := os.ReadFile(outputFile)
	doc := parseJSONPolicy(t, data)
	stmts := doc["Statement"].([]any)
	if len(stmts) == 0 {
		t.Fatal("expected statements")
	}

	stmt := stmts[0].(map[string]any)
	actions := stmt["Action"].([]any)
	found := false
	for _, a := range actions {
		if a.(string) == "dynamodb:GetItem" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected dynamodb:GetItem, got %v", actions)
	}

	resource := stmt["Resource"].(string)
	if !strings.Contains(resource, "table/Users") {
		t.Errorf("Resource = %q, should contain table/Users", resource)
	}
}

func TestIntegration_RunLambda(t *testing.T) {
	binary := buildBinary(t)
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "policy.json")

	cmd := exec.Command(binary, "run", "--output", outputFile, "--",
		"aws", "lambda", "invoke", "--function-name", "MyFunction", "/tmp/out.json")
	cmd.Run()

	data, _ := os.ReadFile(outputFile)
	doc := parseJSONPolicy(t, data)
	stmts := doc["Statement"].([]any)
	if len(stmts) == 0 {
		t.Fatal("expected statements")
	}

	stmt := stmts[0].(map[string]any)
	resource := stmt["Resource"].(string)
	if !strings.Contains(resource, "function:MyFunction") {
		t.Errorf("Resource = %q, should contain function:MyFunction", resource)
	}
}

// --- Parse command tests ---

func TestIntegration_ParseError(t *testing.T) {
	binary := buildBinary(t)

	errorMsg := "User: arn:aws:iam::123456789:user/dev is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::my-bucket/secret.txt"

	cmd := exec.Command(binary, "parse", "--error", errorMsg)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("parse --error failed: %v", err)
	}

	doc := parseJSONPolicy(t, output)
	stmts := doc["Statement"].([]any)
	if len(stmts) == 0 {
		t.Fatal("expected statements")
	}

	actions := stmts[0].(map[string]any)["Action"].([]any)
	found := false
	for _, a := range actions {
		if a.(string) == "s3:GetObject" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected s3:GetObject, got %v", actions)
	}

	resource := stmts[0].(map[string]any)["Resource"].(string)
	if !strings.Contains(resource, "my-bucket") {
		t.Errorf("Resource = %q, should contain my-bucket", resource)
	}
}

func TestIntegration_ParseMultipleErrors(t *testing.T) {
	binary := buildBinary(t)

	errors := `User: arn:aws:iam::123:user/dev is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key
User: arn:aws:iam::123:user/dev is not authorized to perform: dynamodb:PutItem on resource: arn:aws:dynamodb:us-east-1:123:table/Users`

	cmd := exec.Command(binary, "parse", "--stdin")
	cmd.Stdin = strings.NewReader(errors)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("parse --stdin failed: %v", err)
	}

	doc := parseJSONPolicy(t, output)
	stmts := doc["Statement"].([]any)
	if len(stmts) < 2 {
		t.Fatalf("expected at least 2 statements, got %d", len(stmts))
	}
}

func TestIntegration_ParseCloudTrailFile(t *testing.T) {
	binary := buildBinary(t)
	tmpDir := t.TempDir()

	cloudtrail := `{"Records":[{"eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"us-east-1","resources":[{"ARN":"arn:aws:s3:::my-bucket/file.txt"}]},{"eventSource":"dynamodb.amazonaws.com","eventName":"PutItem","awsRegion":"us-east-1"}]}`
	trailFile := writeTempFile(t, tmpDir, "trail.json", cloudtrail)

	cmd := exec.Command(binary, "parse", "--cloudtrail", trailFile)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("parse --cloudtrail failed: %v", err)
	}

	doc := parseJSONPolicy(t, output)
	stmts := doc["Statement"].([]any)
	if len(stmts) < 2 {
		t.Fatalf("expected at least 2 statements, got %d", len(stmts))
	}
}

func TestIntegration_ParseCloudTrailToFile(t *testing.T) {
	binary := buildBinary(t)
	tmpDir := t.TempDir()

	cloudtrail := `{"Records":[{"eventSource":"lambda.amazonaws.com","eventName":"InvokeFunction","awsRegion":"eu-west-1"}]}`
	trailFile := writeTempFile(t, tmpDir, "trail.json", cloudtrail)
	outputFile := filepath.Join(tmpDir, "policy.json")

	cmd := exec.Command(binary, "parse", "--cloudtrail", trailFile, "--output", outputFile)
	if err := cmd.Run(); err != nil {
		t.Fatalf("parse --cloudtrail --output failed: %v", err)
	}

	data, _ := os.ReadFile(outputFile)
	doc := parseJSONPolicy(t, data)
	if doc["Version"] != "2012-10-17" {
		t.Error("expected valid policy document")
	}
}

func TestIntegration_ParseNoInput(t *testing.T) {
	binary := buildBinary(t)

	cmd := exec.Command(binary, "parse")
	_, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected error when no input flags given")
	}
}

// --- License key round-trip tests ---

func TestIntegration_LicenseGenerateKeypair(t *testing.T) {
	binary := buildBinary(t)

	cmd := exec.Command(binary, "license", "generate-keypair")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("generate-keypair failed: %v", err)
	}

	var kp map[string]string
	if err := json.Unmarshal(output, &kp); err != nil {
		t.Fatalf("keypair output is not valid JSON: %v", err)
	}
	if kp["public_key"] == "" {
		t.Error("missing public_key")
	}
	if kp["private_key"] == "" {
		t.Error("missing private_key")
	}
}

func TestIntegration_LicenseRoundTrip(t *testing.T) {
	// Generate keypair
	pubKey, privKey := generateTestKeypair(t)

	// Build binary with our test public key
	binary := buildBinaryWithKey(t, pubKey)

	// Generate a Pro license key using the binary
	licenseKey := generateLicenseKey(t, binary, privKey, "test@example.com", "pro", 365)
	if licenseKey == "" {
		t.Fatal("empty license key")
	}

	// Verify license status
	cmd := exec.Command(binary, "license", "status")
	cmd.Env = append(os.Environ(), "IAMPG_LICENSE_KEY="+licenseKey)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("license status failed: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "pro") {
		t.Errorf("license status should show pro tier, got: %s", outputStr)
	}
	if !strings.Contains(outputStr, "test@example.com") {
		t.Errorf("license status should show email, got: %s", outputStr)
	}
}

func TestIntegration_LicenseCommercialTier(t *testing.T) {
	pubKey, privKey := generateTestKeypair(t)
	binary := buildBinaryWithKey(t, pubKey)

	licenseKey := generateLicenseKey(t, binary, privKey, "corp@company.com", "commercial", 365)

	cmd := exec.Command(binary, "license", "status")
	cmd.Env = append(os.Environ(), "IAMPG_LICENSE_KEY="+licenseKey)
	output, _ := cmd.CombinedOutput()

	if !strings.Contains(string(output), "commercial") {
		t.Errorf("expected commercial tier, got: %s", output)
	}
}

// --- Pro features with license tests ---

func TestIntegration_RefineWithLicense(t *testing.T) {
	pubKey, privKey := generateTestKeypair(t)
	binary := buildBinaryWithKey(t, pubKey)
	licenseKey := generateLicenseKey(t, binary, privKey, "test@test.com", "pro", 365)
	tmpDir := t.TempDir()

	policyFile := writeTempFile(t, tmpDir, "policy.json", wildcardPolicy())

	cmd := exec.Command(binary, "refine", "--input", policyFile)
	cmd.Env = append(os.Environ(), "IAMPG_LICENSE_KEY="+licenseKey)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("refine failed: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "wildcard") || !strings.Contains(outputStr, "Issues") {
		t.Errorf("refine should detect wildcards, got: %s", outputStr)
	}
}

func TestIntegration_RefineJSONFormat(t *testing.T) {
	pubKey, privKey := generateTestKeypair(t)
	binary := buildBinaryWithKey(t, pubKey)
	licenseKey := generateLicenseKey(t, binary, privKey, "test@test.com", "pro", 365)
	tmpDir := t.TempDir()

	policyFile := writeTempFile(t, tmpDir, "policy.json", wildcardPolicy())

	cmd := exec.Command(binary, "refine", "--input", policyFile, "--format", "json")
	cmd.Env = append(os.Environ(), "IAMPG_LICENSE_KEY="+licenseKey)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("refine --format json failed: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("refine JSON output is invalid: %v\nContent: %s", err, output)
	}

	issues, ok := result["issues"].([]any)
	if !ok || len(issues) == 0 {
		t.Error("expected issues in JSON output")
	}
}

func TestIntegration_RefineEnforceBlocks(t *testing.T) {
	pubKey, privKey := generateTestKeypair(t)
	binary := buildBinaryWithKey(t, pubKey)
	licenseKey := generateLicenseKey(t, binary, privKey, "test@test.com", "pro", 365)
	tmpDir := t.TempDir()

	policyFile := writeTempFile(t, tmpDir, "policy.json", wildcardPolicy())

	cmd := exec.Command(binary, "refine", "--input", policyFile, "--enforce")
	cmd.Env = append(os.Environ(), "IAMPG_LICENSE_KEY="+licenseKey)
	err := cmd.Run()

	if err == nil {
		t.Error("refine --enforce should fail for wildcard policy")
	}
}

func TestIntegration_RefineEnforcePassesCleanPolicy(t *testing.T) {
	pubKey, privKey := generateTestKeypair(t)
	binary := buildBinaryWithKey(t, pubKey)
	licenseKey := generateLicenseKey(t, binary, privKey, "test@test.com", "pro", 365)
	tmpDir := t.TempDir()

	policyFile := writeTempFile(t, tmpDir, "policy.json", samplePolicy())

	cmd := exec.Command(binary, "refine", "--input", policyFile, "--enforce")
	cmd.Env = append(os.Environ(), "IAMPG_LICENSE_KEY="+licenseKey)
	err := cmd.Run()

	if err != nil {
		t.Errorf("refine --enforce should pass for clean policy, got: %v", err)
	}
}

func TestIntegration_RefineRequiresLicense(t *testing.T) {
	binary := buildBinary(t)
	tmpDir := t.TempDir()
	policyFile := writeTempFile(t, tmpDir, "policy.json", samplePolicy())

	cmd := exec.Command(binary, "refine", "--input", policyFile)
	cmd.Env = append(os.Environ(), "IAMPG_LICENSE_KEY=")
	output, err := cmd.CombinedOutput()

	if err == nil {
		t.Fatal("refine should fail without license")
	}
	if !strings.Contains(string(output), "Pro") {
		t.Errorf("error should mention Pro, got: %s", output)
	}
}

func TestIntegration_RefineDiff(t *testing.T) {
	pubKey, privKey := generateTestKeypair(t)
	binary := buildBinaryWithKey(t, pubKey)
	licenseKey := generateLicenseKey(t, binary, privKey, "test@test.com", "pro", 365)
	tmpDir := t.TempDir()

	baseline := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::bucket/*"}]}`
	current := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject"],"Resource":"arn:aws:s3:::bucket/*"}]}`

	baselineFile := writeTempFile(t, tmpDir, "baseline.json", baseline)
	currentFile := writeTempFile(t, tmpDir, "current.json", current)

	cmd := exec.Command(binary, "refine", "--input", currentFile, "--compare", baselineFile)
	cmd.Env = append(os.Environ(), "IAMPG_LICENSE_KEY="+licenseKey)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("refine --compare failed: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "Added") {
		t.Errorf("diff should show added permissions, got: %s", outputStr)
	}
	if !strings.Contains(outputStr, "s3:PutObject") {
		t.Errorf("diff should mention s3:PutObject, got: %s", outputStr)
	}
	if !strings.Contains(outputStr, "s3:DeleteObject") {
		t.Errorf("diff should mention s3:DeleteObject, got: %s", outputStr)
	}
}

// --- Aggregate tests ---

func TestIntegration_Aggregate(t *testing.T) {
	pubKey, privKey := generateTestKeypair(t)
	binary := buildBinaryWithKey(t, pubKey)
	licenseKey := generateLicenseKey(t, binary, privKey, "test@test.com", "pro", 365)
	tmpDir := t.TempDir()

	policy1 := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::bucket-a/*"}]}`
	policy2 := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:GetItem"],"Resource":"arn:aws:dynamodb:*:*:table/Users"}]}`

	p1 := writeTempFile(t, tmpDir, "p1.json", policy1)
	p2 := writeTempFile(t, tmpDir, "p2.json", policy2)
	outputFile := filepath.Join(tmpDir, "combined.json")

	cmd := exec.Command(binary, "aggregate", "--files", p1+","+p2, "--output", outputFile)
	cmd.Env = append(os.Environ(), "IAMPG_LICENSE_KEY="+licenseKey)
	if err := cmd.Run(); err != nil {
		combined, _ := exec.Command(binary, "aggregate", "--files", p1+","+p2, "--output", outputFile).CombinedOutput()
		t.Fatalf("aggregate failed: %v\nOutput: %s", err, combined)
	}

	data, _ := os.ReadFile(outputFile)
	doc := parseJSONPolicy(t, data)
	stmts := doc["Statement"].([]any)
	if len(stmts) < 2 {
		t.Fatalf("expected at least 2 statements in aggregated policy, got %d", len(stmts))
	}
}

func TestIntegration_AggregateRequiresLicense(t *testing.T) {
	binary := buildBinary(t)
	tmpDir := t.TempDir()

	p1 := writeTempFile(t, tmpDir, "p1.json", samplePolicy())

	cmd := exec.Command(binary, "aggregate", "--files", p1)
	cmd.Env = append(os.Environ(), "IAMPG_LICENSE_KEY=")
	_, err := cmd.CombinedOutput()

	if err == nil {
		t.Error("aggregate should fail without license")
	}
}

// --- Output format tests ---

func TestIntegration_OutputYAML(t *testing.T) {
	pubKey, privKey := generateTestKeypair(t)
	binary := buildBinaryWithKey(t, pubKey)
	licenseKey := generateLicenseKey(t, binary, privKey, "test@test.com", "pro", 365)
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "policy.yaml")

	cmd := exec.Command(binary, "run", "--output", outputFile, "--format", "yaml", "--",
		"aws", "s3", "ls", "s3://test-bucket/")
	cmd.Env = append(os.Environ(), "IAMPG_LICENSE_KEY="+licenseKey)
	cmd.Run()

	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("no output file: %v", err)
	}

	// Verify it's valid YAML
	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("output is not valid YAML: %v\nContent: %s", err, data)
	}
}

func TestIntegration_OutputTerraform(t *testing.T) {
	pubKey, privKey := generateTestKeypair(t)
	binary := buildBinaryWithKey(t, pubKey)
	licenseKey := generateLicenseKey(t, binary, privKey, "test@test.com", "pro", 365)
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "policy.tf")

	cmd := exec.Command(binary, "run", "--output", outputFile, "--format", "terraform",
		"--resource-name", "deploy_role", "--",
		"aws", "s3", "cp", "file.txt", "s3://bucket/key")
	cmd.Env = append(os.Environ(), "IAMPG_LICENSE_KEY="+licenseKey)
	cmd.Run()

	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("no output file: %v", err)
	}

	output := string(data)
	checks := []string{
		`resource "aws_iam_policy"`,
		`"deploy_role"`,
		`policy = <<-EOF`,
		`EOF`,
		`2012-10-17`,
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("Terraform output missing %q\nFull output:\n%s", check, output)
		}
	}

	// Verify the JSON inside the heredoc is valid
	start := strings.Index(output, "<<-EOF\n") + len("<<-EOF\n")
	end := strings.Index(output, "\n  EOF")
	if start > 0 && end > start {
		jsonStr := strings.TrimSpace(output[start:end])
		var parsed map[string]any
		if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
			t.Errorf("JSON inside Terraform heredoc is invalid: %v", err)
		}
	}
}

func TestIntegration_OutputSARIF(t *testing.T) {
	pubKey, privKey := generateTestKeypair(t)
	binary := buildBinaryWithKey(t, pubKey)
	licenseKey := generateLicenseKey(t, binary, privKey, "test@test.com", "pro", 365)
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "policy.sarif")

	cmd := exec.Command(binary, "run", "--output", outputFile, "--format", "sarif", "--",
		"aws", "s3", "ls", "s3://test-bucket/")
	cmd.Env = append(os.Environ(), "IAMPG_LICENSE_KEY="+licenseKey)
	cmd.Run()

	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("no output file: %v", err)
	}

	// Verify it's valid SARIF JSON
	var report map[string]any
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("SARIF output is invalid JSON: %v", err)
	}

	if report["version"] != "2.1.0" {
		t.Errorf("SARIF version = %v, want 2.1.0", report["version"])
	}

	runs := report["runs"].([]any)
	if len(runs) == 0 {
		t.Fatal("expected SARIF runs")
	}

	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	if driver["name"] != "iampg" {
		t.Errorf("SARIF tool name = %v, want iampg", driver["name"])
	}
}

func TestIntegration_OutputFormatRequiresLicense(t *testing.T) {
	binary := buildBinary(t)

	formats := []string{"yaml", "terraform", "sarif"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			cmd := exec.Command(binary, "run", "--format", format, "--", "echo", "test")
			cmd.Env = append(os.Environ(), "IAMPG_LICENSE_KEY=")
			_, err := cmd.CombinedOutput()
			if err == nil {
				t.Errorf("format %s should require license", format)
			}
		})
	}
}

// --- CLI basics ---

func TestIntegration_VersionFlag(t *testing.T) {
	binary := buildBinary(t)

	output, err := exec.Command(binary, "--version").Output()
	if err != nil {
		t.Fatalf("--version failed: %v", err)
	}
	if !strings.Contains(string(output), "iampg") {
		t.Errorf("version should contain 'iampg', got: %s", output)
	}
}

func TestIntegration_HelpFlag(t *testing.T) {
	binary := buildBinary(t)

	output, err := exec.Command(binary, "--help").Output()
	if err != nil {
		t.Fatalf("--help failed: %v", err)
	}

	for _, check := range []string{"run", "parse", "refine", "aggregate"} {
		if !strings.Contains(string(output), check) {
			t.Errorf("help missing %q", check)
		}
	}
}
