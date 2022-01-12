
Root and user volume encryption should be enabled

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  GoodExample:
    Type: AWS::WorkSpaces::Workspace
    Properties:
      RootVolumeEncryptionEnabled: true
      UserVolumeEncryptionEnabled: true
      UserName: "admin"
```
