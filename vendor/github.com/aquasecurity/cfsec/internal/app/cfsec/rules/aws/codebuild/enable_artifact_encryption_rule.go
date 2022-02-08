package codebuild

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/codebuild"
)

func init() {

	scanner.RegisterCheckRule(rules.Rule{
		BadExample: []string{`---
Resources:
  GoodProject:
    Type: AWS::CodeBuild::Project
    Properties:
      Artifacts:
        ArtifactIdentifier: "String"
        EncryptionDisabled: true
        Location: "String"
        Name: "String"
        NamespaceType: "String"
        OverrideArtifactName: false
        Packaging: "String"
        Path: "String"
        Type: "String"
      SecondaryArtifacts:
        - ArtifactIdentifier: "String"
          EncryptionDisabled: false
          Location: "String"
          Name: "String"
          NamespaceType: "String"
          OverrideArtifactName: false
          Packaging: "String"
          Path: "String"
          Type: "String"
`,
			`---
Resources:
  GoodProject:
    Type: AWS::CodeBuild::Project
    Properties:
      Artifacts:
        ArtifactIdentifier: "String"
        EncryptionDisabled: false
        Location: "String"
        Name: "String"
        NamespaceType: "String"
        OverrideArtifactName: false
        Packaging: "String"
        Path: "String"
        Type: "String"
      SecondaryArtifacts:
        - ArtifactIdentifier: "String"
          EncryptionDisabled: true
          Location: "String"
          Name: "String"
          NamespaceType: "String"
          OverrideArtifactName: false
          Packaging: "String"
          Path: "String"
          Type: "String"
`},

		GoodExample: []string{`---
Resources:
  GoodProject:
    Type: AWS::CodeBuild::Project
    Properties:
      Artifacts:
        ArtifactIdentifier: "String"
        EncryptionDisabled: false
        Location: "String"
        Name: "String"
        NamespaceType: "String"
        OverrideArtifactName: false
        Packaging: "String"
        Path: "String"
        Type: "String"
      SecondaryArtifacts:
        - ArtifactIdentifier: "String"
          EncryptionDisabled: false
          Location: "String"
          Name: "String"
          NamespaceType: "String"
          OverrideArtifactName: false
          Packaging: "String"
          Path: "String"
          Type: "String"
`},

		Base: codebuild.CheckEnableEncryption,
	})
}
