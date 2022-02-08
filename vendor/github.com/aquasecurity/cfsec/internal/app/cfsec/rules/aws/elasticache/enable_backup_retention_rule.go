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
  BadExample:
    Type: AWS::ElastiCache::CacheCluster
    Properties:
      AZMode: cross-az
      CacheNodeType: cache.m3.medium
      Engine: redis
      NumCacheNodes: '3'
      PreferredAvailabilityZones:
        - us-west-2a
        - us-west-2a
        - us-west-2b 
`},
		GoodExample: []string{`---
Resources:
  GoodExample:
    Type: AWS::ElastiCache::CacheCluster
    Properties:
      AZMode: cross-az
      CacheNodeType: cache.m3.medium
      Engine: redis
      NumCacheNodes: '3'
      SnapshotRetentionLimit: 7
      PreferredAvailabilityZones:
        - us-west-2a
        - us-west-2a
        - us-west-2b 
`},
		Base: elasticache.CheckEnableBackupRetention,
	})
}
