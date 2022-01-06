---
additional_links: []
---

Set the instance to not be publicly accessible

```yaml
---
Resources:
  GoodExample:
    Properties:
      ImageId: ami-123456
      InstanceType: t2.small
    Type: AWS::AutoScaling::LaunchConfiguration
```
