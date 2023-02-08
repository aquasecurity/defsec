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
		})

		launchTemplate := ec2.LaunchTemplate{
			Metadata:               r.Metadata(),
			Id:                     types.String("", r.Metadata()),
			DefaultVersion:         r.GetIntProperty("DefaultVersionNumber"),
			LaunchTemplateVersions: LTV,
			Instance: ec2.Instance{
				Metadata: r.Metadata(),
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
			launchTemplate.Instance.UserData = data.GetStringProperty("UserData", "")

			blockDevices := getBlockDevices(r)
			for i, device := range blockDevices {
				copyDevice := device
				if i == 0 {
					launchTemplate.RootBlockDevice = copyDevice
					continue
				}
				launchTemplate.EBSBlockDevices = append(launchTemplate.EBSBlockDevices, device)
			}
		}

		templates = append(templates, launchTemplate)

	}
	return templates
}
