package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getLaunchTemplates(file parser.FileContext) (templates []ec2.LaunchTemplate) {
	launchConfigResources := file.GetResourcesByType("AWS::EC2::LaunchTemplate")

	for _, r := range launchConfigResources {

		var LTV []ec2.LaunchTemplateVersion
		var imageid types.StringValue
		if data := r.GetProperty("LaunchTemplateData"); data.IsNotNil() {
			imageid = data.GetStringProperty("ImageId")
		}
		LTV = append(LTV, ec2.LaunchTemplateVersion{
			Metadata: r.Metadata(),
			LaunchTemplateData: ec2.LaunchTemplateData{
				Metadata: r.Metadata(),
				ImageId:  imageid,
			},
			VersionNumber: types.IntDefault(0, r.Metadata()),
		})

		launchTemplate := ec2.LaunchTemplate{
			Metadata:               r.Metadata(),
			Id:                     types.String("", r.Metadata()),
			DefaultVersion:         r.GetIntProperty("DefaultVersionNumber"),
			LaunchTemplateVersions: LTV,
			Instance: ec2.Instance{
				Metadata:              r.Metadata(),
				VPCId:                 types.StringDefault("", r.Metadata()),
				ImageId:               types.StringDefault("", r.Metadata()),
				SubnetId:              types.StringDefault("", r.Metadata()),
				InstanceId:            types.StringDefault("", r.Metadata()),
				InstanceType:          types.StringDefault("", r.Metadata()),
				InstanceLifecycle:     types.StringDefault("", r.Metadata()),
				StateName:             types.StringDefault("", r.Metadata()),
				IamInstanceProfile:    types.String("", r.Metadata()),
				PublicIpAddress:       types.String("", r.Metadata()),
				MonitoringState:       types.BoolDefault(false, r.Metadata()),
				KeyName:               types.StringDefault("", r.Metadata()),
				SpotInstanceRequestId: types.StringDefault("", r.Metadata()),
				MetadataOptions: ec2.MetadataOptions{
					Metadata:     r.Metadata(),
					HttpTokens:   types.StringDefault("optional", r.Metadata()),
					HttpEndpoint: types.StringDefault("enabled", r.Metadata()),
				},
				UserData:        types.StringDefault("", r.Metadata()),
				SecurityGroups:  nil,
				RootBlockDevice: nil,
				EBSBlockDevices: nil,
			},
		}

		if data := r.GetProperty("LaunchTemplateData"); data.IsNotNil() {
			if opts := data.GetProperty("MetadataOptions"); opts.IsNotNil() {
				launchTemplate.MetadataOptions = ec2.MetadataOptions{
					Metadata:     opts.Metadata(),
					HttpTokens:   opts.GetStringProperty("HttpTokens", "optional"),
					HttpEndpoint: opts.GetStringProperty("HttpEndpoint", "enabled"),
				}
			}
			launchTemplate.UserData = data.GetStringProperty("UserData", "")
			launchTemplate.Instance.ImageId = data.GetStringProperty("ImageId", "")
			launchTemplate.Instance.InstanceType = data.GetStringProperty("InstanceType", "")
			launchTemplate.Instance.IamInstanceProfile = data.GetStringProperty("IamInstanceProfile.Arn", "")
			launchTemplate.Instance.KeyName = data.GetStringProperty("KeyName", "")
			launchTemplate.Instance.MonitoringState = data.GetBoolProperty("Monitoring.Enabled")

			blockDevices := getBlockDevices(r)
			for i, device := range blockDevices {
				copyDevice := device
				if i == 0 {
					launchTemplate.Instance.RootBlockDevice = copyDevice
					continue
				}
				launchTemplate.Instance.EBSBlockDevices = append(launchTemplate.Instance.EBSBlockDevices, device)
			}
		}

		templates = append(templates, launchTemplate)

	}
	return templates
}
