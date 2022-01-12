
Add a logging block to the resource to enable access logging

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  GoodExample:
    Properties:
      AccessControl: Private
    Type: AWS::S3::Bucket
```
