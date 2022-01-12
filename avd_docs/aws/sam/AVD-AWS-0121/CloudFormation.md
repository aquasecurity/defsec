
Enable server side encryption

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM Table
Resources:
  GoodFunction:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: GoodTable
      SSESpecification:
        SSEEnabled: true
```
