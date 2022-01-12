
Add descriptions for all security groups and rules

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
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
```
