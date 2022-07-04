package arn

import (
	"fmt"
	"strings"
)

// https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-arn-format.html
// arn:partition:service:region:namespace:relative-id

type ARN struct {
	Partition  string
	Service    string
	Region     string
	Namespace  string
	RelativeID string
}

func New(service, region, namespace, id string) ARN {
	return ARN{
		Partition:  "aws",
		Service:    service,
		Region:     region,
		Namespace:  namespace,
		RelativeID: id,
	}
}

func From(arn string) ARN {
	var a ARN
	a.Partition = "aws"
	parts := strings.Split(arn, ":")
	if len(parts) > 1 {
		a.Partition = parts[1]
	}
	if len(parts) > 2 {
		a.Service = parts[2]
	}
	if len(parts) > 3 {
		a.Region = parts[3]
	}
	if len(parts) > 4 {
		a.Namespace = parts[4]
	}
	if len(parts) > 5 {
		a.RelativeID = parts[5]
	}
	return a
}

func (a ARN) String() string {
	return fmt.Sprintf("arn:%s:%s:%s:%s:%s", a.Partition, a.Service, a.Region, a.Namespace, a.RelativeID)
}
