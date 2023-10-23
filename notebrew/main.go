package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func main() {
	type S3Credentials struct {
		EndpointURL     string `json:"endpointURL,omitempty"`
		Region          string `json:"region,omitempty"`
		Bucket          string `json:"bucket,omitempty"`
		AccessKeyID     string `json:"accessKeyID,omitempty"`
		SecretAccessKey string `json:"secretAccessKey,omitempty"`
	}
	var creds S3Credentials
	b, err := os.ReadFile(`C:/Users/bokwoonchua/notebrew-admin/config/s3.json`)
	if err != nil {
		log.Fatal(err)
	}
	// TODO: use a decoder instead, and DisallowUnknownFields
	err = json.Unmarshal(b, &creds)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%#v\n", creds)
	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(creds.EndpointURL),
		Region:       creds.Region,
		Credentials:  aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, "")),
	})
	filePath := `C:/Users/bokwoonchua/Pictures/bing.png`
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	putObjectOutput, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(creds.Bucket),
		Key:    aws.String(filePath),
		Body:   file,
	})
	if err != nil {
		log.Fatal(err)
	}
	b, err = json.MarshalIndent(putObjectOutput, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(b))
	// TODO: GetObject (make sure exists) -> DeleteObject -> GetObject (make sure not exists)
}
