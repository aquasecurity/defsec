package autoscaling

var cloudformationEnforceHttpTokenImdsGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::IAM::InstanceProfile
    Properties:
      InstanceProfileName: MyIamInstanceProfile
      Path: "/"
      Roles:
      - MyAdminRole
  MyLaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateName: MyLaunchTemplate
      LaunchTemplateData:
        IamInstanceProfile:
          Arn: !GetAtt
            - MyIamInstanceProfile
            - Arn
        DisableApiTermination: true
        ImageId: ami-04d5cc9b88example
        UserData: export SSM_PATH=/database/creds
        InstanceType: t2.micro
        KeyName: MyKeyPair
        MetadataOptions:
          - HttpTokens: required
        SecurityGroupIds:
          - sg-083cd3bfb8example
 `,
}

var cloudformationEnforceHttpTokenImdsBadExamples = []string{
	`---
Resources:
  BadExample:
  Type: AWS::IAM::InstanceProfile
  Properties:
    InstanceProfileName: MyIamInstanceProfile
    Path: "/"
    Roles:
    - MyAdminRole
  MyLaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateName: MyLaunchTemplate
      LaunchTemplateData:
        IamInstanceProfile:
          Arn: !GetAtt
            - MyIamInstanceProfile
            - Arn
        DisableApiTermination: true
        ImageId: ami-04d5cc9b88example
        InstanceType: t2.micro
        KeyName: MyKeyPair
        MetadataOptions:
          - HttpTokens: optional
        SecurityGroupIds:
          - sg-083cd3bfb8example
 `,
}

var cloudformationEnforceHttpTokenImdsLinks = []string{}

var cloudformationEnforceHttpTokenImdsRemediationMarkdown = ``
