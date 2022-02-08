package rds

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/rds"
)

func init() {
	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: false

`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: true
      PerformanceInsightsKMSKeyId: "something"

`,
		},
		Base: rds.CheckEnablePerformanceInsights,
	})
}
