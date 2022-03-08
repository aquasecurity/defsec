
Enable Performance Insights to detect potential problems

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: true
```
