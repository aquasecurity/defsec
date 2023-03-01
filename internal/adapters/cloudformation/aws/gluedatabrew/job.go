package gluedatabrew

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/gluedatabrew"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getJobs(ctx parser.FileContext) []gluedatabrew.Job {
	resources := ctx.GetResourcesByType("AWS::DataBrew::Job")

	var jobs []gluedatabrew.Job
	for _, r := range resources {
		jobs = append(jobs, gluedatabrew.Job{
			Metadata:         r.Metadata(),
			EncryptionMode:   r.GetStringProperty("EncryptionMode"),
			EncryptionKeyArn: r.GetStringProperty("EncryptionKeyArn"),
		})
	}
	return jobs
}
