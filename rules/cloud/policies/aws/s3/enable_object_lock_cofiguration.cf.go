package s3

var cloudFormationEnableObjectLockConfigurationGoodExamples = []string{
	`
Resources:
  GoodExample:
    Properties:
      ObjectLockConfiguration:
        - ObjectLockEnabled: "Enabled"
            ObjectLockRule:
               	Days: 10
 				Mode: "COMPLIANCE"
  				Years: 0
    Type: AWS::S3::Bucket
`,
}

var cloudFormationEnableObjectLockConfigurationBadExamples = []string{
	`---
Resources:
  BadExample:
    Properties:
      ObjectLock:
        ObjectLockConfiguration:
          
    Type: AWS::S3::Bucket
`,
}

var cloudFormationEnableObjectLockConfigurationLinks = []string{}

var cloudFormationEnableObjectLockConfigurationRemediationMarkdown = ``
