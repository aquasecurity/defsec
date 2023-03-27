
Set the database to not be publicly accessible

```yaml---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: false


```


