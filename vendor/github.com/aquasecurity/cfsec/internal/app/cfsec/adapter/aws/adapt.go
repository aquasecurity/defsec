package aws

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/apigateway"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/athena"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/autoscaling"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/cloudfront"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/cloudtrail"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/cloudwatch"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/codebuild"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/config"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/documentdb"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/dynamodb"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/ebs"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/ec2"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/ecr"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/ecs"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/efs"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/eks"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/elasticache"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/elasticsearch"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/elb"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/iam"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/kinesis"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/lambda"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/mq"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/msk"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/neptune"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/rds"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/redshift"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/s3"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/sns"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/sqs"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/ssm"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/vpc"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/workspaces"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) aws.AWS {
	return aws.AWS{
		APIGateway:    apigateway.Adapt(cfFile),
		Athena:        athena.Adapt(cfFile),
		Autoscaling:   autoscaling.Adapt(cfFile),
		Cloudfront:    cloudfront.Adapt(cfFile),
		CloudTrail:    cloudtrail.Adapt(cfFile),
		CloudWatch:    cloudwatch.Adapt(cfFile),
		CodeBuild:     codebuild.Adapt(cfFile),
		Config:        config.Adapt(cfFile),
		DocumentDB:    documentdb.Adapt(cfFile),
		DynamoDB:      dynamodb.Adapt(cfFile),
		EBS:           ebs.Adapt(cfFile),
		EC2:           ec2.Adapt(cfFile),
		ECR:           ecr.Adapt(cfFile),
		ECS:           ecs.Adapt(cfFile),
		EFS:           efs.Adapt(cfFile),
		IAM:           iam.Adapt(cfFile),
		EKS:           eks.Adapt(cfFile),
		ElastiCache:   elasticache.Adapt(cfFile),
		Elasticsearch: elasticsearch.Adapt(cfFile),
		ELB:           elb.Adapt(cfFile),
		MSK:           msk.Adapt(cfFile),
		MQ:            mq.Adapt(cfFile),
		Kinesis:       kinesis.Adapt(cfFile),
		Lambda:        lambda.Adapt(cfFile),
		Neptune:       neptune.Adapt(cfFile),
		RDS:           rds.Adapt(cfFile),
		Redshift:      redshift.Adapt(cfFile),
		S3:            s3.Adapt(cfFile),
		SNS:           sns.Adapt(cfFile),
		SQS:           sqs.Adapt(cfFile),
		SSM:           ssm.Adapt(cfFile),
		VPC:           vpc.Adapt(cfFile),
		WorkSpaces:    workspaces.Adapt(cfFile),
	}
}