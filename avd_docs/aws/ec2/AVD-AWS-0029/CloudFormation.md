---
additional_links: []
---

Remove sensitive data from the EC2 instance user-data

```yaml
---
Resources:
  GoodExample:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: "ami-79fd7eee"
      KeyName: "testkey"
      UserData: export SSM_PATH=/database/creds
      BlockDeviceMappings:
        - DeviceName: "/dev/sdm"
          Ebs:
            VolumeType: "io1"
            Iops: "200"
            DeleteOnTermination: "false"
            VolumeSize: "20"
        - DeviceName: "/dev/sdk"
```
