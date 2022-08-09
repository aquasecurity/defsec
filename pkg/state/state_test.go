package state

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"

	"github.com/stretchr/testify/assert"
)

func Test_RegoConversion(t *testing.T) {
	s := State{
		AWS: aws.AWS{
			S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: types2.NewMetadata(
							types2.NewRange("main.tf", 2, 4, "", nil),
							types2.NewNamedReference("aws_s3_bucket.example"),
						),
						Name: types2.String("my-bucket", types2.NewMetadata(
							types2.NewRange("main.tf", 3, 3, "", nil),
							types2.NewNamedReference("aws_s3_bucket.example.bucket"),
						)),
					},
				},
			},
		},
	}
	converted := s.ToRego()
	assert.Equal(t, map[string]interface{}{
		"aws": map[string]interface{}{
			"s3": map[string]interface{}{
				"buckets": []interface{}{
					map[string]interface{}{
						"__defsec_metadata": map[string]interface{}{
							"resource":  "aws_s3_bucket.example",
							"filepath":  "main.tf",
							"startline": 2,
							"endline":   4,
							"managed":   true,
							"explicit":  false,
							"fskey":     "",
						},
						"name": map[string]interface{}{
							"resource":  "aws_s3_bucket.example.bucket",
							"filepath":  "main.tf",
							"startline": 3,
							"endline":   3,
							"value":     "my-bucket",
							"managed":   true,
							"explicit":  false,
							"fskey":     "",
						},
					},
				},
			},
		},
	}, converted)
}
