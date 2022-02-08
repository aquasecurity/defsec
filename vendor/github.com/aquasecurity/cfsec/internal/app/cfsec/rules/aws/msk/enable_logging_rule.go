package rds

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/msk"
)

func init() {
	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Cluster:
    Type: AWS::MSK::Cluster
    Properties:
      LoggingInfo:
        BrokerLogs:
          CloudWatchLogs:
            Enabled: false

`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Cluster:
    Type: AWS::MSK::Cluster
    Properties:
      LoggingInfo:
        BrokerLogs:
          S3:
            Enabled: true


`,
		},
		Base: msk.CheckEnableLogging,
	})
}
