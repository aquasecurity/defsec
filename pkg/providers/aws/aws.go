package aws

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/accessanalyzer"
	"github.com/aquasecurity/defsec/pkg/providers/aws/apigateway"
	"github.com/aquasecurity/defsec/pkg/providers/aws/appflow"
	"github.com/aquasecurity/defsec/pkg/providers/aws/apprunner"
	"github.com/aquasecurity/defsec/pkg/providers/aws/athena"
	"github.com/aquasecurity/defsec/pkg/providers/aws/auditmanager"
	"github.com/aquasecurity/defsec/pkg/providers/aws/autoscaling"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudfront"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudtrail"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudwatch"
	"github.com/aquasecurity/defsec/pkg/providers/aws/codebuild"
	"github.com/aquasecurity/defsec/pkg/providers/aws/config"
	"github.com/aquasecurity/defsec/pkg/providers/aws/documentdb"
	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ecr"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ecs"
	"github.com/aquasecurity/defsec/pkg/providers/aws/efs"
	"github.com/aquasecurity/defsec/pkg/providers/aws/eks"
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticache"
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticsearch"
	"github.com/aquasecurity/defsec/pkg/providers/aws/elb"
	"github.com/aquasecurity/defsec/pkg/providers/aws/emr"
	"github.com/aquasecurity/defsec/pkg/providers/aws/finspace"
	"github.com/aquasecurity/defsec/pkg/providers/aws/firehose"
	"github.com/aquasecurity/defsec/pkg/providers/aws/forecast"
	"github.com/aquasecurity/defsec/pkg/providers/aws/frauddetector"
	"github.com/aquasecurity/defsec/pkg/providers/aws/fsx"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/providers/aws/kendra"
	"github.com/aquasecurity/defsec/pkg/providers/aws/kinesis"
	"github.com/aquasecurity/defsec/pkg/providers/aws/kinesisvideo"
	"github.com/aquasecurity/defsec/pkg/providers/aws/kms"
	"github.com/aquasecurity/defsec/pkg/providers/aws/lambda"
	"github.com/aquasecurity/defsec/pkg/providers/aws/mq"
	"github.com/aquasecurity/defsec/pkg/providers/aws/msk"
	"github.com/aquasecurity/defsec/pkg/providers/aws/neptune"
	"github.com/aquasecurity/defsec/pkg/providers/aws/proton"
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/providers/aws/redshift"
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sam"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ses"
	"github.com/aquasecurity/defsec/pkg/providers/aws/shield"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sns"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sqs"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ssm"
	"github.com/aquasecurity/defsec/pkg/providers/aws/timestreamwrite"
	"github.com/aquasecurity/defsec/pkg/providers/aws/transfer"
	"github.com/aquasecurity/defsec/pkg/providers/aws/translate"
	"github.com/aquasecurity/defsec/pkg/providers/aws/waf"
	"github.com/aquasecurity/defsec/pkg/providers/aws/wafv2"
	"github.com/aquasecurity/defsec/pkg/providers/aws/workspaces"
	"github.com/aquasecurity/defsec/pkg/providers/aws/xray"
)

type AWS struct {
	AccessAnalyzer  accessanalyzer.AccessAnalyzer
	Auditmanager    auditmanager.AuditManager
	Appflow         appflow.Appflow
	Apprunner       apprunner.Apprunner
	Autoscaling     autoscaling.Autoscaling
	APIGateway      apigateway.APIGateway
	Athena          athena.Athena
	Cloudfront      cloudfront.Cloudfront
	CloudTrail      cloudtrail.CloudTrail
	CloudWatch      cloudwatch.CloudWatch
	CodeBuild       codebuild.CodeBuild
	Config          config.Config
	DocumentDB      documentdb.DocumentDB
	DynamoDB        dynamodb.DynamoDB
	EC2             ec2.EC2
	ECR             ecr.ECR
	ECS             ecs.ECS
	EFS             efs.EFS
	EKS             eks.EKS
	ElastiCache     elasticache.ElastiCache
	Elasticsearch   elasticsearch.Elasticsearch
	ELB             elb.ELB
	EMR             emr.EMR
	Finspace        finspace.ListEnvironements
	Firehose        firehose.Firehose
	Forecast        forecast.Forecast
	Frauddetector   frauddetector.Frauddetector
	Fsx             fsx.Fsx
	IAM             iam.IAM
	Kinesis         kinesis.Kinesis
	Kinesisvideo    kinesisvideo.Kinesisvideo
	Kendra          kendra.Kendra
	KMS             kms.KMS
	Lambda          lambda.Lambda
	MQ              mq.MQ
	MSK             msk.MSK
	Neptune         neptune.Neptune
	Proton          proton.Proton
	RDS             rds.RDS
	Redshift        redshift.Redshift
	SAM             sam.SAM
	S3              s3.S3
	SNS             sns.SNS
	SQS             sqs.SQS
	SES             ses.Ses
	Shield          shield.Shield
	SSM             ssm.SSM
	Timestreamwrite timestreamwrite.Timestream_write
	Translate       translate.Translate
	Transfer        transfer.Transfer
	Waf             waf.Waf
	Wafv2           wafv2.Wafv2
	WorkSpaces      workspaces.WorkSpaces
	Xray            xray.Xray
}
