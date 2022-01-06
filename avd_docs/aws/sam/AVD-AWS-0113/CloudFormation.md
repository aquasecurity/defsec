---
additional_links: []
---

Enable logging for API Gateway stages

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM API
Resources:
  ApiGatewayApi:
    Type: AWS::Serverless::Api
    Properties:
      Name: Good SAM API example
      StageName: Prod
      TracingEnabled: false
      Domain:
        SecurityPolicy: TLS_1_2
      AccessLogSetting:
        DestinationArn: gateway-logging
        Format: json
```
