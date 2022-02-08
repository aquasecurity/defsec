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
Description: Bad example of redshift cluster
Resources:
  Queue:
    Type: AWS::Redshift::Cluster
    Properties:
      ClusterSubnetGroupName: ""

`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of redshift cluster
Resources:
  Queue:
    Type: AWS::Redshift::Cluster
    Properties:
      ClusterSubnetGroupName: "my-subnet-group"

`,
		},
		Base: redshift.CheckUsesVPC,
	})
}
