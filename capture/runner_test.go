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
