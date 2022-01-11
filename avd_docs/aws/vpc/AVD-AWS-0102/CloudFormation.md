
Set specific allowed ports

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
```
