package lambda

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/lambda"
)

func init() {

	scanner.RegisterCheckRule(rules.Rule{
		BadExample: []string{`---
Resources:
  BadExample:
    Type: AWS::Lambda::Function
    Properties:
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/lambda-role
      Code:
        S3Bucket: my-bucket
        S3Key: function.zip
      Runtime: nodejs12.x
      Timeout: 5
      TracingConfig:
        Mode: Active
      VpcConfig:
        SecurityGroupIds:
          - sg-085912345678492fb
        SubnetIds:
          - subnet-071f712345678e7c8
          - subnet-07fd123456788a036
  BadPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref BadExample
      Action: lambda:InvokeFunction
      Principal: s3.amazonaws.com

`},
		GoodExample: []string{`---
Resources:
  GoodExample:
    Type: AWS::Lambda::Function
    Properties:
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/lambda-role
      Code:
        S3Bucket: my-bucket
        S3Key: function.zip
      Runtime: nodejs12.x
      Timeout: 5
      TracingConfig:
        Mode: Active
      VpcConfig:
        SecurityGroupIds:
          - sg-085912345678492fb
        SubnetIds:
          - subnet-071f712345678e7c8
          - subnet-07fd123456788a036
  GoodPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref BadExample
      Action: lambda:InvokeFunction
      Principal: s3.amazonaws.com
      SourceArn: "lambda.amazonaws.com"
  
`},
		Base: lambda.CheckRestrictSourceArn,
	})
}
