
Turn on encryption for all block devices

```yaml
---
Resources:
  GoodExample:
    Properties:
      BlockDeviceMappings:
        - DeviceName: root
          Ebs:
            Encrypted: true
      ImageId: ami-123456
      InstanceType: t2.small
    Type: AWS::AutoScaling::LaunchConfiguration
```
