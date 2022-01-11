
Use secrets for the task definition

```yaml
---
Resources:
  GoodExample:
    Type: 'AWS::ECS::Cluster'
    Properties:
      ClusterName: MyCluster
      ClusterSettings:
        - Name: containerInsights
          Value: enabled
  GoodTask:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: "CFSec scan"
      Cpu: 512
      Memory: 1024
      NetworkMode: awsvpc
      RequiresCompatibilities:
        - FARGATE
        - EC2
      ContainerDefinitions:
        - Name: cfsec
          Image: cfsec/cfsec:latest
          MountPoints:
            - SourceVolume: src
              ContainerPath: /src
          LogConfiguration:
            LogDriver: awslogs
            Options:
              awslogs-group: "cfsec-logs"
              awslogs-region: !Ref AWS::Region
              awslogs-stream-prefix: "cfsec"
      Volumes:
        - Name: jenkins-home
          EFSVolumeConfiguration:
            FilesystemId: "fs1"
            TransitEncryption: ENABLED
```
