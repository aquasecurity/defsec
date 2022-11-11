
Enable Object Lock Configuration using customer managed keys

```yaml
Resources:
  GoodExample:
    Properties:
      ObjectLockEnabled: false
      ObjectLockConfiguration:
        ObjectLockEnabled: 'Enabled'
        Rule:
          DefaultRetention:
            Mode: 'COMPLIANCE'
            Days: 120
    Type: AWS::S3::Bucket

```


