package ecs

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/ecs"
)

func init() {

	scanner.RegisterCheckRule(rules.Rule{
		BadExample: []string{`---
Resources:
  BadExample:
    Type: 'AWS::ECS::Cluster'
    Properties:
      ClusterName: MyCluster
      ClusterSettings:
        - Name: containerInsights
          Value: enabled
  BadTask:
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
            TransitEncryption: DISABLED`},
		GoodExample: []string{`---
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
`},
		Base: ecs.CheckEnableInTransitEncryption,
	})

}
