package iam

import (
	"strings"
	"time"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/state"
	iamapi "github.com/aws/aws-sdk-go-v2/service/iam"
)

func (a *adapter) adaptCredentialReport(state *state.State) error {
	a.Tracker().SetServiceLabel("Discovering credential reports...")

	input := &iamapi.GenerateCredentialReportInput{}
	for {
		_, err := a.api.GenerateCredentialReport(a.Context(), input)
		if err != nil && strings.Contains(err.Error(), "ReportInProgress") {
			time.Sleep(5 * time.Second)
		} else {
			break
		}
		if err != nil {
			return err
		}

	}

	var reportData [][]string
	var reportErr error

	for {
		resp, err := a.api.GetCredentialReport(a.Context(), &iamapi.GetCredentialReportInput{})
		if err != nil {
			return err
		}
		reportBytes := resp.Content
		reportStr := string(reportBytes)
		// Parse CSV content
		reportLines := strings.Split(reportStr, "\n")
		if len(reportLines) == 0 {
			continue
		}

		reportData = make([][]string, len(reportLines)-1)
		for i, line := range reportLines[1:] {
			fields := strings.Split(line, ",")
			reportData[i] = make([]string, len(fields))
			for i, line := range reportLines[1:] {
				fields := strings.Split(line, ",")
				reportData[i] = make([]string, len(fields))
				copy(reportData[i], fields)
			}
		}
		reportErr = nil
		break
	}
	if reportErr != nil {
		return reportErr
	}

	a.Tracker().SetServiceLabel("Adapting server certificates...")

	state.AWS.IAM.CredentialReports = concurrency.Adapt(reportData, a.RootAdapter, a.adaptReport)
	return nil
}

func (a *adapter) adaptReport(reportdata []string) (*iam.CredentialReport, error) {

	metadata := a.CreateMetadata(reportdata[1])
	report := iam.CredentialReport{
		Metadata:                       metadata,
		User:                           defsecTypes.String(reportdata[0], metadata),
		Arn:                            defsecTypes.String(reportdata[1], metadata),
		User_creation_time:             defsecTypes.String(reportdata[2], metadata),
		Password_enabled:               defsecTypes.String(reportdata[3], metadata),
		Password_last_used:             defsecTypes.String(reportdata[4], metadata),
		Password_last_changed:          defsecTypes.String(reportdata[5], metadata),
		Password_next_rotation:         defsecTypes.String(reportdata[6], metadata),
		Mfa_active:                     defsecTypes.String(reportdata[7], metadata),
		Access_key_1_active:            defsecTypes.String(reportdata[8], metadata),
		Access_key_1_last_rotated:      defsecTypes.String(reportdata[9], metadata),
		Access_key_1_last_used_date:    defsecTypes.String(reportdata[10], metadata),
		Access_key_1_last_used_region:  defsecTypes.String(reportdata[11], metadata),
		Access_key_1_last_used_service: defsecTypes.String(reportdata[12], metadata),
		Access_key_2_active:            defsecTypes.String(reportdata[13], metadata),
		Access_key_2_last_rotated:      defsecTypes.String(reportdata[14], metadata),
		Access_key_2_last_used_date:    defsecTypes.String(reportdata[15], metadata),
		Access_key_2_last_used_region:  defsecTypes.String(reportdata[16], metadata),
		Access_key_2_last_used_service: defsecTypes.String(reportdata[17], metadata),
		Cert_1_active:                  defsecTypes.String(reportdata[18], metadata),
		Cert_1_last_rotated:            defsecTypes.String(reportdata[19], metadata),
		Cert_2_active:                  defsecTypes.String(reportdata[20], metadata),
		Cert_2_last_rotated:            defsecTypes.String(reportdata[21], metadata),
	}

	return &report, nil
}
