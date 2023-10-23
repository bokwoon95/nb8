package main

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func main() {
	type S3Credentials struct {
		AccessKeyID     string `json:"accessKeyID,omitempty"`
		SecretAccessKey string `json:"secretAccessKey,omitempty"`
	}
	var creds S3Credentials
	// TODO: unmarshal config/s3.json
	client := s3.New(s3.Options{
		Region:      "us-west-004",
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, "")),
	})
	_ = client
}
