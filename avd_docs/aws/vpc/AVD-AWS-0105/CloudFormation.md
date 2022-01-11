
Set a more restrictive cidr range

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Godd example of excessive ports
Resources: 
  NetworkACL:
    Type: AWS::EC2::NetworkAcl
    Properties:
      VpcId: "something"
  Rule:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
      NetworkAclId:
        Ref: NetworkACL
      Protocol: 6
      CidrBlock: 10.0.0.0/8
      RuleAction: allow
```
