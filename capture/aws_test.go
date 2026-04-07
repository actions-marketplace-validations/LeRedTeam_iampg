// Copyright (C) 2026 LeRedTeam
// SPDX-License-Identifier: AGPL-3.0-or-later

package capture

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func makeRequest(method, rawURL string, headers map[string]string, body string) (*http.Request, []byte) {
	u, _ := url.Parse(rawURL)
	req := &http.Request{
		Method: method,
		URL:    u,
		Host:   u.Host,
		Header: make(http.Header),
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, []byte(body)
}

// --- parseAWSHost tests ---

func TestParseAWSHost_StandardService(t *testing.T) {
	tests := []struct {
		host    string
		service string
		region  string
	}{
		{"dynamodb.us-east-1.amazonaws.com", "dynamodb", "us-east-1"},
		{"lambda.eu-west-1.amazonaws.com", "lambda", "eu-west-1"},
		{"sqs.us-west-2.amazonaws.com", "sqs", "us-west-2"},
		{"sns.ap-southeast-1.amazonaws.com", "sns", "ap-southeast-1"},
		{"sts.amazonaws.com", "sts", ""},
		{"iam.amazonaws.com", "iam", ""},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			service, region := parseAWSHost(tt.host)
			if service != tt.service {
				t.Errorf("service = %q, want %q", service, tt.service)
			}
			if region != tt.region {
				t.Errorf("region = %q, want %q", region, tt.region)
			}
		})
	}
}

func TestParseAWSHost_S3BucketStyle(t *testing.T) {
	tests := []struct {
		host   string
		region string
	}{
		{"my-bucket.s3.amazonaws.com", ""},
		{"my-bucket.s3.us-east-1.amazonaws.com", "us-east-1"},
		{"some.dotted.bucket.s3.eu-west-1.amazonaws.com", "eu-west-1"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			service, region := parseAWSHost(tt.host)
			if service != "s3" {
				t.Errorf("service = %q, want s3", service)
			}
			if region != tt.region {
				t.Errorf("region = %q, want %q", region, tt.region)
			}
		})
	}
}

func TestParseAWSHost_S3RegionalPrefix(t *testing.T) {
	service, _ := parseAWSHost("s3-us-west-2.amazonaws.com")
	if service != "s3" {
		t.Errorf("service = %q, want s3", service)
	}
}

func TestParseAWSHost_NonAWS(t *testing.T) {
	service, _ := parseAWSHost("example.com")
	if service != "" {
		t.Errorf("expected empty service for non-AWS host, got %q", service)
	}
}

// --- S3 action parsing ---

func TestParseS3Action_GetObject(t *testing.T) {
	req, body := makeRequest("GET", "https://s3.amazonaws.com/bucket/key.txt", nil, "")
	call := ParseAWSRequest(req, body)
	if call == nil {
		t.Fatal("expected call")
	}
	if call.Action != "GetObject" {
		t.Errorf("Action = %q, want GetObject", call.Action)
	}
}

func TestParseS3Action_PutObject(t *testing.T) {
	req, body := makeRequest("PUT", "https://s3.amazonaws.com/bucket/key.txt", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "PutObject" {
		t.Errorf("Action = %q, want PutObject", call.Action)
	}
}

func TestParseS3Action_DeleteObject(t *testing.T) {
	req, body := makeRequest("DELETE", "https://s3.amazonaws.com/bucket/key.txt", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "DeleteObject" {
		t.Errorf("Action = %q, want DeleteObject", call.Action)
	}
}

func TestParseS3Action_ListBucket(t *testing.T) {
	req, body := makeRequest("GET", "https://s3.amazonaws.com/bucket/", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "ListBucket" {
		t.Errorf("Action = %q, want ListBucket", call.Action)
	}
}

func TestParseS3Action_HeadObject(t *testing.T) {
	req, body := makeRequest("HEAD", "https://s3.amazonaws.com/bucket/key.txt", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "HeadObject" {
		t.Errorf("Action = %q, want HeadObject", call.Action)
	}
}

func TestParseS3Action_CreateBucket(t *testing.T) {
	req, body := makeRequest("PUT", "https://s3.amazonaws.com/new-bucket", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "CreateBucket" {
		t.Errorf("Action = %q, want CreateBucket", call.Action)
	}
}

func TestParseS3Action_Versioning(t *testing.T) {
	req, body := makeRequest("GET", "https://s3.amazonaws.com/bucket?versioning", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "GetBucketVersioning" {
		t.Errorf("Action = %q, want GetBucketVersioning", call.Action)
	}

	req, body = makeRequest("PUT", "https://s3.amazonaws.com/bucket?versioning", nil, "")
	call = ParseAWSRequest(req, body)
	if call.Action != "PutBucketVersioning" {
		t.Errorf("Action = %q, want PutBucketVersioning", call.Action)
	}
}

func TestParseS3Action_Lifecycle(t *testing.T) {
	req, body := makeRequest("GET", "https://s3.amazonaws.com/bucket?lifecycle", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "GetLifecycleConfiguration" {
		t.Errorf("Action = %q, want GetLifecycleConfiguration", call.Action)
	}
}

func TestParseS3Action_Policy(t *testing.T) {
	req, body := makeRequest("GET", "https://s3.amazonaws.com/bucket?policy", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "GetBucketPolicy" {
		t.Errorf("Action = %q, want GetBucketPolicy", call.Action)
	}
}

func TestParseS3Action_ACL(t *testing.T) {
	req, body := makeRequest("PUT", "https://s3.amazonaws.com/bucket/key?acl", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "PutObjectAcl" {
		t.Errorf("Action = %q, want PutObjectAcl", call.Action)
	}
}

func TestParseS3Action_Uploads(t *testing.T) {
	req, body := makeRequest("GET", "https://s3.amazonaws.com/bucket?uploads", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "ListMultipartUploads" {
		t.Errorf("Action = %q, want ListMultipartUploads", call.Action)
	}
}

// --- S3 resource parsing ---

func TestParseS3Resource_PathStyle(t *testing.T) {
	req, body := makeRequest("GET", "https://s3.amazonaws.com/my-bucket/path/to/key", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Resource != "arn:aws:s3:::my-bucket/path/to/key" {
		t.Errorf("Resource = %q, want arn:aws:s3:::my-bucket/path/to/key", call.Resource)
	}
}

func TestParseS3Resource_BucketStyle(t *testing.T) {
	req, body := makeRequest("GET", "https://my-bucket.s3.amazonaws.com/key.txt", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Resource != "arn:aws:s3:::my-bucket/key.txt" {
		t.Errorf("Resource = %q, want arn:aws:s3:::my-bucket/key.txt", call.Resource)
	}
}

func TestParseS3Resource_BucketOnly(t *testing.T) {
	req, body := makeRequest("GET", "https://s3.amazonaws.com/my-bucket/", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Resource != "arn:aws:s3:::my-bucket" {
		t.Errorf("Resource = %q, want arn:aws:s3:::my-bucket", call.Resource)
	}
}

func TestParseS3Resource_NoBucket(t *testing.T) {
	req, body := makeRequest("GET", "https://s3.amazonaws.com/", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Resource != "arn:aws:s3:::*" {
		t.Errorf("Resource = %q, want arn:aws:s3:::*", call.Resource)
	}
}

// --- DynamoDB ---

func TestParseDynamoDB(t *testing.T) {
	req, body := makeRequest("POST", "https://dynamodb.us-east-1.amazonaws.com/",
		map[string]string{"X-Amz-Target": "DynamoDB_20120810.GetItem"},
		`{"TableName":"Users","Key":{"id":{"S":"123"}}}`)

	call := ParseAWSRequest(req, body)
	if call == nil {
		t.Fatal("expected call")
	}
	if call.Service != "dynamodb" {
		t.Errorf("Service = %q, want dynamodb", call.Service)
	}
	if call.Action != "GetItem" {
		t.Errorf("Action = %q, want GetItem", call.Action)
	}
	if call.Region != "us-east-1" {
		t.Errorf("Region = %q, want us-east-1", call.Region)
	}
	if !strings.Contains(call.Resource, "table/Users") {
		t.Errorf("Resource = %q, should contain table/Users", call.Resource)
	}
}

func TestParseDynamoDB_NoTableName(t *testing.T) {
	req, body := makeRequest("POST", "https://dynamodb.us-east-1.amazonaws.com/",
		map[string]string{"X-Amz-Target": "DynamoDB_20120810.ListTables"},
		`{}`)

	call := ParseAWSRequest(req, body)
	if call.Resource != "*" {
		t.Errorf("Resource = %q, want * when no table name", call.Resource)
	}
}

// --- Lambda ---

func TestParseLambda_Invoke(t *testing.T) {
	req, body := makeRequest("POST", "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/MyFunc/invocations", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "InvokeFunction" {
		t.Errorf("Action = %q, want InvokeFunction", call.Action)
	}
	if !strings.Contains(call.Resource, "function:MyFunc") {
		t.Errorf("Resource = %q, should contain function:MyFunc", call.Resource)
	}
}

func TestParseLambda_GetFunction(t *testing.T) {
	req, body := makeRequest("GET", "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/MyFunc", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "GetFunction" {
		t.Errorf("Action = %q, want GetFunction", call.Action)
	}
}

func TestParseLambda_CreateFunction(t *testing.T) {
	req, body := makeRequest("POST", "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "CreateFunction" {
		t.Errorf("Action = %q, want CreateFunction", call.Action)
	}
}

// --- SQS ---

func TestParseSQS_QueryParam(t *testing.T) {
	req, body := makeRequest("GET", "https://sqs.us-east-1.amazonaws.com/123456789/my-queue?Action=SendMessage", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "SendMessage" {
		t.Errorf("Action = %q, want SendMessage", call.Action)
	}
	if !strings.Contains(call.Resource, "123456789:my-queue") {
		t.Errorf("Resource = %q, should contain account and queue", call.Resource)
	}
}

func TestParseSQS_FormData(t *testing.T) {
	req, body := makeRequest("POST", "https://sqs.us-east-1.amazonaws.com/123456789/my-queue", nil, "Action=ReceiveMessage&MaxNumberOfMessages=10")
	call := ParseAWSRequest(req, body)
	if call.Action != "ReceiveMessage" {
		t.Errorf("Action = %q, want ReceiveMessage", call.Action)
	}
}

// --- SNS ---

func TestParseSNS(t *testing.T) {
	req, body := makeRequest("GET", "https://sns.us-east-1.amazonaws.com/?Action=Publish&TopicArn=arn:aws:sns:us-east-1:123:MyTopic", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "Publish" {
		t.Errorf("Action = %q, want Publish", call.Action)
	}
}

// --- STS ---

func TestParseSTS(t *testing.T) {
	req, body := makeRequest("POST", "https://sts.amazonaws.com/", nil, "Action=AssumeRole&RoleArn=arn:aws:iam::123:role/MyRole")
	call := ParseAWSRequest(req, body)
	if call.Action != "AssumeRole" {
		t.Errorf("Action = %q, want AssumeRole", call.Action)
	}
}

// --- IAM ---

func TestParseIAM(t *testing.T) {
	req, body := makeRequest("POST", "https://iam.amazonaws.com/", nil, "Action=CreateUser&UserName=testuser")
	call := ParseAWSRequest(req, body)
	if call.Action != "CreateUser" {
		t.Errorf("Action = %q, want CreateUser", call.Action)
	}
}

// --- Generic ---

func TestParseGeneric_XAmzTarget(t *testing.T) {
	req, body := makeRequest("POST", "https://glue.us-east-1.amazonaws.com/",
		map[string]string{"X-Amz-Target": "AWSGlue.GetDatabase"}, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "GetDatabase" {
		t.Errorf("Action = %q, want GetDatabase", call.Action)
	}
}

func TestParseGeneric_QueryAction(t *testing.T) {
	req, body := makeRequest("GET", "https://cloudwatch.us-east-1.amazonaws.com/?Action=DescribeAlarms", nil, "")
	call := ParseAWSRequest(req, body)
	if call.Action != "DescribeAlarms" {
		t.Errorf("Action = %q, want DescribeAlarms", call.Action)
	}
}

// --- Non-AWS ---

func TestParseNonAWS(t *testing.T) {
	req, body := makeRequest("GET", "https://example.com/api/data", nil, "")
	call := ParseAWSRequest(req, body)
	if call != nil {
		t.Error("expected nil for non-AWS request")
	}
}

func TestParseEmptyHost(t *testing.T) {
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Host: "", Path: "/"},
		Header: make(http.Header),
	}
	call := ParseAWSRequest(req, nil)
	if call != nil {
		t.Error("expected nil for empty host")
	}
}
