---
additional_links: []
---

Enable logging for API Gateway stages

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of ApiGateway
Resources:
  GoodApi:
    Type: AWS::ApiGatewayV2::Api
  GoodApiStage:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      AccessLogSettings:
        DestinationArn: gateway-logging
        Format: json
      ApiId: !Ref GoodApi
      StageName: GoodApiStage
```
