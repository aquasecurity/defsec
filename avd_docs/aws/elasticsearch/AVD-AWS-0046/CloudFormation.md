
Enforce the use of HTTPS for ElasticSearch

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  GoodExample:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainName: 'test'
      DomainEndpointOptions:
        EnforceHTTPS: true
        
      ElasticsearchVersion: '7.10'
      EncryptionAtRestOptions:
        Enabled: true
        KmsKeyId: alias/kmskey
      ElasticsearchClusterConfig:
        DedicatedMasterEnabled: true
        InstanceCount: '2'
        ZoneAwarenessEnabled: true
        InstanceType: 'm3.medium.elasticsearch'
        DedicatedMasterType: 'm3.medium.elasticsearch'
        DedicatedMasterCount: '3'
      EBSOptions:
        EBSEnabled: true
        Iops: '0'
        VolumeSize: '20'
        VolumeType: 'gp2'
```
