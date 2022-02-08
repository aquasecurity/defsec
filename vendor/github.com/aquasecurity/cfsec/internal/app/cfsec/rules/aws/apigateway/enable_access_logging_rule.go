package apigateway

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/apigateway"
)

func init() {
	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of ApiGateway
Resources:
  BadApi:
    Type: AWS::ApiGatewayV2::Api
  BadApiStage:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      AccessLogSettings:
        Format: json
      ApiId: !Ref BadApi
      StageName: BadApiStage
`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of ApiGateway
Resources:
  GoodApi:
    Type: AWS::ApiGatewayV2::Api
  GoodApiStage:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      AccessLogSettings:
        DestinationArn: gateway-logging
        Format: json
      ApiId: !Ref GoodApi
      StageName: GoodApiStage
`,
		},

		Base: apigateway.CheckEnableAccessLogging,
	})
}
