
Set the instance to not be publicly accessible

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  GoodExample:
    Properties:
      ImageId: ami-123456
      InstanceType: t2.small
    Type: AWS::AutoScaling::LaunchConfiguration
```
