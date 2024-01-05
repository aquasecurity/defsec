
Define user session termination duration

```yaml---
Type: AWS::SSO::PermissionSet
Properties:
  Description: "An example"
  InstanceArn: String
  Name: "Example"
  SessionDuration: "PT2H"
```