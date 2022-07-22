package ec2

type EC2 struct {
	Instances            []Instance
	LaunchConfigurations []LaunchConfiguration
	LaunchTemplates      []LaunchTemplate
	DefaultVPCs          []DefaultVPC
	SecurityGroups       []SecurityGroup
	NetworkACLs          []NetworkACL
	Volumes              []Volume
}
