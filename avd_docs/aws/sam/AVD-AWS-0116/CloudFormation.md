
Enable logging for API Gateway stages

```yaml---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM API
Resources:
  ApiGatewayApi:
    Type: AWS::Serverless::HttpApi
    Properties:
      Name: Good SAM API example
      StageName: Prod
      Tracing: Activey
      AccessLogSettings:
        DestinationArn: gateway-logging
        Format: json

```


