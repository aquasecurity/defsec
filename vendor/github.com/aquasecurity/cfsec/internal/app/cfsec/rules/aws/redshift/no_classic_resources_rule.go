package redshift

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/redshift"
)

func init() {
	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of redshift sgr
Resources:
  Queue:
    Type: AWS::Redshift::ClusterSecurityGroup
    Properties:
      Description: ""

`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of redshift sgr
Resources:

`,
		},
		Base: redshift.CheckNoClassicResources,
	})
}
