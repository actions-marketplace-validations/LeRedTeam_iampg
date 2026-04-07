// Copyright (C) 2026 LeRedTeam
// SPDX-License-Identifier: AGPL-3.0-or-later

package capture

import (
	"testing"
)

func TestParseAWSCLIArgs_S3LsBucket(t *testing.T) {
	args := []string{"aws", "s3", "ls", "s3://my-bucket/"}

	call := parseAWSCLIArgs(args)

	if call == nil {
		t.Fatal("expected call, got nil")
	}
	if call.Service != "s3" {
		t.Errorf("expected service s3, got %s", call.Service)
	}
	if call.Action != "ListBucket" {
		t.Errorf("expected action ListBucket, got %s", call.Action)
	}
	if call.Resource != "arn:aws:s3:::my-bucket/*" {
		t.Errorf("expected resource arn:aws:s3:::my-bucket/*, got %s", call.Resource)
	}
}

func TestParseAWSCLIArgs_S3LsAllBuckets(t *testing.T) {
	args := []string{"aws", "s3", "ls"}

	call := parseAWSCLIArgs(args)

	if call == nil {
		t.Fatal("expected call, got nil")
	}
	if call.Action != "ListAllMyBuckets" {
		t.Errorf("expected action ListAllMyBuckets, got %s", call.Action)
	}
	if call.Resource != "*" {
		t.Errorf("expected resource *, got %s", call.Resource)
	}
}

func TestParseAWSCLIArgs_S3Cp(t *testing.T) {
	args := []string{"aws", "s3", "cp", "file.txt", "s3://bucket/folder/file.txt"}

	call := parseAWSCLIArgs(args)

	if call == nil {
		t.Fatal("expected call, got nil")
	}
	if call.Action != "PutObject" {
		t.Errorf("expected action PutObject, got %s", call.Action)
	}
	if call.Resource != "arn:aws:s3:::bucket/folder/file.txt" {
		t.Errorf("unexpected resource: %s", call.Resource)
	}
}

func TestParseAWSCLIArgs_S3CpDownload(t *testing.T) {
	args := []string{"aws", "s3", "cp", "s3://bucket/folder/file.txt", "/tmp/local.txt"}

	call := parseAWSCLIArgs(args)

	if call == nil {
		t.Fatal("expected call, got nil")
	}
	if call.Action != "GetObject" {
		t.Errorf("expected action GetObject for download, got %s", call.Action)
	}
}

func TestParseAWSCLIArgs_S3MvDownload(t *testing.T) {
	args := []string{"aws", "s3", "mv", "s3://bucket/file.txt", "/tmp/local.txt"}

	call := parseAWSCLIArgs(args)

	if call == nil {
		t.Fatal("expected call, got nil")
	}
	if call.Action != "GetObject" {
		t.Errorf("expected action GetObject for mv download, got %s", call.Action)
	}
}

func TestParseAWSCLIArgs_S3MvUpload(t *testing.T) {
	args := []string{"aws", "s3", "mv", "/tmp/local.txt", "s3://bucket/file.txt"}

	call := parseAWSCLIArgs(args)

	if call == nil {
		t.Fatal("expected call, got nil")
	}
	if call.Action != "PutObject" {
		t.Errorf("expected action PutObject for mv upload, got %s", call.Action)
	}
}

func TestParseAWSCLIArgs_S3Rm(t *testing.T) {
	args := []string{"aws", "s3", "rm", "s3://bucket/file.txt"}

	call := parseAWSCLIArgs(args)

	if call == nil {
		t.Fatal("expected call, got nil")
	}
	if call.Action != "DeleteObject" {
		t.Errorf("expected action DeleteObject, got %s", call.Action)
	}
}

func TestParseAWSCLIArgs_DynamoDB(t *testing.T) {
	args := []string{"aws", "dynamodb", "put-item", "--table-name", "Users", "--item", `{"id":{"S":"1"}}`}

	call := parseAWSCLIArgs(args)

	if call == nil {
		t.Fatal("expected call, got nil")
	}
	if call.Service != "dynamodb" {
		t.Errorf("expected service dynamodb, got %s", call.Service)
	}
	if call.Action != "PutItem" {
		t.Errorf("expected action PutItem, got %s", call.Action)
	}
	if call.Resource != "arn:aws:dynamodb:*:*:table/Users" {
		t.Errorf("unexpected resource: %s", call.Resource)
	}
}

func TestParseAWSCLIArgs_S3LsRecursive(t *testing.T) {
	args := []string{"aws", "s3", "ls", "--recursive", "s3://my-bucket/"}

	call := parseAWSCLIArgs(args)

	if call == nil {
		t.Fatal("expected call, got nil")
	}
	if call.Action != "ListBucket" {
		t.Errorf("expected action ListBucket, got %s", call.Action)
	}
	if call.Resource != "arn:aws:s3:::my-bucket/*" {
		t.Errorf("expected resource arn:aws:s3:::my-bucket/*, got %s", call.Resource)
	}
}

func TestParseAWSCLIArgs_S3CpNoSignRequest(t *testing.T) {
	args := []string{"aws", "s3", "cp", "--no-sign-request", "s3://bucket/file.txt", "/tmp/file.txt"}

	call := parseAWSCLIArgs(args)

	if call == nil {
		t.Fatal("expected call, got nil")
	}
	if call.Action != "GetObject" {
		t.Errorf("expected action GetObject for download with --no-sign-request, got %s", call.Action)
	}
}

func TestParseAWSCLIArgs_Lambda(t *testing.T) {
	args := []string{"aws", "lambda", "invoke", "--function-name", "MyFunc", "output.json"}

	call := parseAWSCLIArgs(args)

	if call == nil {
		t.Fatal("expected call, got nil")
	}
	if call.Service != "lambda" {
		t.Errorf("expected service lambda, got %s", call.Service)
	}
	if call.Action != "Invoke" {
		t.Errorf("expected action Invoke, got %s", call.Action)
	}
	if call.Resource != "arn:aws:lambda:*:*:function:MyFunc" {
		t.Errorf("unexpected resource: %s", call.Resource)
	}
}

func TestParseAWSCLIArgs_WithFlags(t *testing.T) {
	args := []string{"aws", "--profile", "prod", "s3", "ls", "s3://bucket/", "--region", "us-west-2"}

	call := parseAWSCLIArgs(args)

	if call == nil {
		t.Fatal("expected call, got nil")
	}
	if call.Service != "s3" {
		t.Errorf("expected service s3, got %s", call.Service)
	}
	if call.Action != "ListBucket" {
		t.Errorf("expected action ListBucket, got %s", call.Action)
	}
}

func TestParseAWSCLIArgs_NotAWS(t *testing.T) {
	args := []string{"ls", "-la"}

	call := parseAWSCLIArgs(args)

	if call != nil {
		t.Error("expected nil for non-AWS command")
	}
}

func TestParseAWSCLIArgs_TooShort(t *testing.T) {
	args := []string{"aws", "s3"}

	call := parseAWSCLIArgs(args)

	if call != nil {
		t.Error("expected nil for incomplete command")
	}
}

func TestParseAWSCLIArgs_S3API_HeadObject(t *testing.T) {
	args := []string{"aws", "s3api", "head-object", "--bucket", "my-bucket", "--key", "path/to/file.txt"}

	call := parseAWSCLIArgs(args)

	if call == nil {
		t.Fatal("expected call, got nil")
	}
	if call.Service != "s3" {
		t.Errorf("expected service s3, got %s", call.Service)
	}
	if call.Action != "HeadObject" {
		t.Errorf("expected action HeadObject, got %s", call.Action)
	}
	if call.Resource != "arn:aws:s3:::my-bucket/path/to/file.txt" {
		t.Errorf("expected resource with bucket and key, got %s", call.Resource)
	}
}

func TestParseAWSCLIArgs_S3API_ListObjectsV2(t *testing.T) {
	args := []string{"aws", "s3api", "list-objects-v2", "--bucket", "my-bucket"}

	call := parseAWSCLIArgs(args)

	if call == nil {
		t.Fatal("expected call, got nil")
	}
	if call.Service != "s3" {
		t.Errorf("expected service s3, got %s", call.Service)
	}
	if call.Action != "ListObjectsV2" {
		t.Errorf("expected action ListObjectsV2, got %s", call.Action)
	}
	if call.Resource != "arn:aws:s3:::my-bucket" {
		t.Errorf("expected resource with bucket only, got %s", call.Resource)
	}
}

func TestCliCommandToAction_S3(t *testing.T) {
	// Note: "ls" is handled specially in parseAWSCLIArgs, not here
	tests := map[string]string{
		"cp":      "PutObject",
		"mv":      "PutObject",
		"rm":      "DeleteObject",
		"mb":      "CreateBucket",
		"rb":      "DeleteBucket",
		"sync":    "PutObject",
		"presign": "GetObject",
	}

	for cmd, expected := range tests {
		result := cliCommandToAction("s3", cmd)
		if result != expected {
			t.Errorf("s3 %s: expected %s, got %s", cmd, expected, result)
		}
	}
}

func TestCliCommandToAction_Generic(t *testing.T) {
	tests := map[string]string{
		"put-item":        "PutItem",
		"get-item":        "GetItem",
		"invoke":          "Invoke",
		"create-function": "CreateFunction",
		"list-buckets":    "ListBuckets",
	}

	for cmd, expected := range tests {
		result := cliCommandToAction("dynamodb", cmd)
		if result != expected {
			t.Errorf("%s: expected %s, got %s", cmd, expected, result)
		}
	}
}

// --- Resource extraction tests ---

func TestExtractS3Resource_S3Path(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			"bucket and key",
			[]string{"aws", "s3", "cp", "file.txt", "s3://my-bucket/folder/file.txt"},
			"arn:aws:s3:::my-bucket/folder/file.txt",
		},
		{
			"bucket only",
			[]string{"aws", "s3", "ls", "s3://my-bucket/"},
			"arn:aws:s3:::my-bucket/*",
		},
		{
			"no s3 path",
			[]string{"aws", "s3", "ls"},
			"arn:aws:s3:::*",
		},
		{
			"bucket with nested key",
			[]string{"aws", "s3", "cp", "s3://bucket/a/b/c/d.txt", "local.txt"},
			"arn:aws:s3:::bucket/a/b/c/d.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractS3Resource(tt.args)
			if got != tt.want {
				t.Errorf("extractS3Resource = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractS3Resource_S3API(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			"bucket and key flags",
			[]string{"aws", "s3api", "get-object", "--bucket", "my-bucket", "--key", "path/file.txt"},
			"arn:aws:s3:::my-bucket/path/file.txt",
		},
		{
			"bucket only flag",
			[]string{"aws", "s3api", "list-objects", "--bucket", "my-bucket"},
			"arn:aws:s3:::my-bucket",
		},
		{
			"no bucket flag",
			[]string{"aws", "s3api", "list-buckets"},
			"arn:aws:s3:::*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractS3Resource(tt.args)
			if got != tt.want {
				t.Errorf("extractS3Resource = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractDynamoDBResource(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			"with table name",
			[]string{"aws", "dynamodb", "get-item", "--table-name", "Users"},
			"arn:aws:dynamodb:*:*:table/Users",
		},
		{
			"without table name",
			[]string{"aws", "dynamodb", "list-tables"},
			"*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDynamoDBResource(tt.args)
			if got != tt.want {
				t.Errorf("extractDynamoDBResource = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractLambdaResource(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			"with function name",
			[]string{"aws", "lambda", "invoke", "--function-name", "MyFunc", "out.json"},
			"arn:aws:lambda:*:*:function:MyFunc",
		},
		{
			"without function name",
			[]string{"aws", "lambda", "list-functions"},
			"*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractLambdaResource(tt.args)
			if got != tt.want {
				t.Errorf("extractLambdaResource = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractSQSResource(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			"with queue URL",
			[]string{"aws", "sqs", "send-message", "--queue-url", "https://sqs.us-east-1.amazonaws.com/123456789/my-queue"},
			"arn:aws:sqs:*:123456789:my-queue",
		},
		{
			"without queue URL",
			[]string{"aws", "sqs", "list-queues"},
			"*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSQSResource(tt.args)
			if got != tt.want {
				t.Errorf("extractSQSResource = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractSNSResource(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			"with topic ARN",
			[]string{"aws", "sns", "publish", "--topic-arn", "arn:aws:sns:us-east-1:123:MyTopic", "--message", "hello"},
			"arn:aws:sns:us-east-1:123:MyTopic",
		},
		{
			"with target ARN",
			[]string{"aws", "sns", "publish", "--target-arn", "arn:aws:sns:us-east-1:123:endpoint/abc"},
			"arn:aws:sns:us-east-1:123:endpoint/abc",
		},
		{
			"without ARN",
			[]string{"aws", "sns", "list-topics"},
			"*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSNSResource(tt.args)
			if got != tt.want {
				t.Errorf("extractSNSResource = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractSTSResource(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			"with role ARN",
			[]string{"aws", "sts", "assume-role", "--role-arn", "arn:aws:iam::123:role/DeployRole", "--role-session-name", "test"},
			"arn:aws:iam::123:role/DeployRole",
		},
		{
			"get-caller-identity",
			[]string{"aws", "sts", "get-caller-identity"},
			"*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSTSResource(tt.args)
			if got != tt.want {
				t.Errorf("extractSTSResource = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractIAMResource(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			"with role name",
			[]string{"aws", "iam", "get-role", "--role-name", "MyRole"},
			"arn:aws:iam::*:role/MyRole",
		},
		{
			"with user name",
			[]string{"aws", "iam", "get-user", "--user-name", "alice"},
			"arn:aws:iam::*:user/alice",
		},
		{
			"with policy ARN",
			[]string{"aws", "iam", "get-policy", "--policy-arn", "arn:aws:iam::123:policy/MyPolicy"},
			"arn:aws:iam::123:policy/MyPolicy",
		},
		{
			"with group name",
			[]string{"aws", "iam", "get-group", "--group-name", "Developers"},
			"arn:aws:iam::*:group/Developers",
		},
		{
			"list roles",
			[]string{"aws", "iam", "list-roles"},
			"*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIAMResource(tt.args)
			if got != tt.want {
				t.Errorf("extractIAMResource = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractSecretsManagerResource(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			"with secret name",
			[]string{"aws", "secretsmanager", "get-secret-value", "--secret-id", "prod/db-password"},
			"arn:aws:secretsmanager:*:*:secret:prod/db-password",
		},
		{
			"with secret ARN",
			[]string{"aws", "secretsmanager", "get-secret-value", "--secret-id", "arn:aws:secretsmanager:us-east-1:123:secret:mysecret-AbCdEf"},
			"arn:aws:secretsmanager:us-east-1:123:secret:mysecret-AbCdEf",
		},
		{
			"list secrets",
			[]string{"aws", "secretsmanager", "list-secrets"},
			"*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSecretsManagerResource(tt.args)
			if got != tt.want {
				t.Errorf("extractSecretsManagerResource = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractSSMResource(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			"with parameter name",
			[]string{"aws", "ssm", "get-parameter", "--name", "/prod/db/host"},
			"arn:aws:ssm:*:*:parameter/prod/db/host",
		},
		{
			"with parameter ARN",
			[]string{"aws", "ssm", "get-parameter", "--name", "arn:aws:ssm:us-east-1:123:parameter/myapp/config"},
			"arn:aws:ssm:us-east-1:123:parameter/myapp/config",
		},
		{
			"describe parameters",
			[]string{"aws", "ssm", "describe-parameters"},
			"*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSSMResource(tt.args)
			if got != tt.want {
				t.Errorf("extractSSMResource = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractCloudWatchLogsResource(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			"with log group",
			[]string{"aws", "logs", "describe-log-streams", "--log-group-name", "/aws/lambda/my-function"},
			"arn:aws:logs:*:*:log-group:/aws/lambda/my-function",
		},
		{
			"describe log groups",
			[]string{"aws", "logs", "describe-log-groups"},
			"*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCloudWatchLogsResource(tt.args)
			if got != tt.want {
				t.Errorf("extractCloudWatchLogsResource = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractKMSResource(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			"with key ID",
			[]string{"aws", "kms", "describe-key", "--key-id", "1234abcd-12ab-34cd-56ef-1234567890ab"},
			"arn:aws:kms:*:*:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		},
		{
			"with key ARN",
			[]string{"aws", "kms", "encrypt", "--key-id", "arn:aws:kms:us-east-1:123:key/1234abcd"},
			"arn:aws:kms:us-east-1:123:key/1234abcd",
		},
		{
			"with alias",
			[]string{"aws", "kms", "describe-key", "--alias-name", "alias/my-key"},
			"arn:aws:kms:*:*:alias/my-key",
		},
		{
			"list keys",
			[]string{"aws", "kms", "list-keys"},
			"*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractKMSResource(tt.args)
			if got != tt.want {
				t.Errorf("extractKMSResource = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractResourceFromArgs_Dispatch(t *testing.T) {
	// Unknown service should return *
	got := extractResourceFromArgs("ec2", "describe-instances", []string{"aws", "ec2", "describe-instances"})
	if got != "*" {
		t.Errorf("unknown service resource = %q, want *", got)
	}
}
