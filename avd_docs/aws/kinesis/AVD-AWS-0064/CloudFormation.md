
Enable in transit encryption

```yaml---
Resources:
  GoodExample:
    Type: AWS::Kinesis::Stream
    Properties:
      Name: GoodExample
      RetentionPeriodHours: 168
      ShardCount: 3
      StreamEncryption:
        EncryptionType: KMS
        KeyId: alis/key
      Tags:
        -
          Key: Environment 
          Value: Production

```


