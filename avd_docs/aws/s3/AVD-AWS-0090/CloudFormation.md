---
additional_links: []
---

Enable versioning to protect against accidental/malicious removal or modification

```yaml
---
Resources:
  GoodExample:
    Properties:
      VersioningConfiguration:
        Status: Enabled
    Type: AWS::S3::Bucket
```
