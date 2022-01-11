
Set a more restrictive cidr range

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of egress rule
Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupEgress:
      - CidrIp: 127.0.0.1/32
        IpProtocol: "6"
```
