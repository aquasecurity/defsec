package elasticache

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/elasticache"
)

func init() {

	scanner.RegisterCheckRule(rules.Rule{
		BadExample: []string{`---
Resources:
  BadExampleCacheGroup:
    Type: AWS::ElastiCache::SecurityGroup
    Properties:
      Tags:
      - Name: BadExample
  BadExampleEc2SecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: BadExample
      GroupDescription: Bad Elasticache Security Group
  BadSecurityGroupIngress:
    Type: AWS::ElastiCache::SecurityGroupIngress
    Properties: 
      CacheSecurityGroupName: BadExampleCacheGroup
      EC2SecurityGroupName: BadExampleEc2SecurityGroup
`},
		GoodExample: []string{`---
Resources:
  GoodExampleCacheGroup:
    Type: AWS::ElastiCache::SecurityGroup
    Properties:
      Description: Some description
  GoodExampleEc2SecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: GoodExample
      GroupDescription: Good Elasticache Security Group
  GoodSecurityGroupIngress:
    Type: AWS::ElastiCache::SecurityGroupIngress
    Properties: 
      CacheSecurityGroupName: GoodExampleCacheGroup
      EC2SecurityGroupName: GoodExampleEc2SecurityGroup
`},
		Base: elasticache.CheckAddDescriptionForSecurityGroup,
	})
}
