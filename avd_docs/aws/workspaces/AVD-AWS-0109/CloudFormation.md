---
additional_links: []
---

Root and user volume encryption should be enabled

```yaml
---
Resources:
  GoodExample:
    Type: AWS::WorkSpaces::Workspace
    Properties:
      RootVolumeEncryptionEnabled: true
      UserVolumeEncryptionEnabled: true
      UserName: "admin"
```
