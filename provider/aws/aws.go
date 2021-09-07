package aws

import (
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/defsec/provider/aws/athena"
	"github.com/aquasecurity/defsec/provider/aws/autoscaling"
	"github.com/aquasecurity/defsec/provider/aws/cloudfront"
	"github.com/aquasecurity/defsec/provider/aws/cloudtrail"
	"github.com/aquasecurity/defsec/provider/aws/cloudwatch"
	"github.com/aquasecurity/defsec/provider/aws/codebuild"
	"github.com/aquasecurity/defsec/provider/aws/config"
	"github.com/aquasecurity/defsec/provider/aws/documentdb"
	"github.com/aquasecurity/defsec/provider/aws/dynamodb"
	"github.com/aquasecurity/defsec/provider/aws/ebs"
	"github.com/aquasecurity/defsec/provider/aws/ec2"
	"github.com/aquasecurity/defsec/provider/aws/ecr"
	"github.com/aquasecurity/defsec/provider/aws/ecs"
	"github.com/aquasecurity/defsec/provider/aws/efs"
	"github.com/aquasecurity/defsec/provider/aws/eks"
	"github.com/aquasecurity/defsec/provider/aws/elasticache"
	"github.com/aquasecurity/defsec/provider/aws/elasticsearch"
	"github.com/aquasecurity/defsec/provider/aws/elb"
	"github.com/aquasecurity/defsec/provider/aws/s3"
)

type AWS struct {
	APIGateway    apigateway.APIGateway
	Athena        athena.Athena
	Autoscaling   autoscaling.Autoscaling
	Cloudfront    cloudfront.Cloudfront
	CloudTrail    cloudtrail.CloudTrail
	CloudWatch    cloudwatch.CloudWatch
	CodeBuild     codebuild.CodeBuild
	Config        config.Config
	DocumentDB    documentdb.DocumentDB
	DynamoDB      dynamodb.DynamoDB
	EBS           ebs.EBS
	EC2           ec2.EC2
	ECR           ecr.ECR
	ECS           ecs.ECS
	EFS           efs.EFS
	EKS           eks.EKS
	ElastiCache   elasticache.ElastiCache
	Elasticsearch elasticsearch.Elasticsearch
	ELB           elb.ELB
	S3            s3.S3
}
