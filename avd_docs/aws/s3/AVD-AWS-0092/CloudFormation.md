
Don't use canned ACLs or switch to private acl

```yaml---
Resources:
  GoodExample:
    Properties:
      AccessControl: Private
    Type: AWS::S3::Bucket

```


