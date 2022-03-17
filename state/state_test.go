package state

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws"
	"github.com/aquasecurity/defsec/providers/aws/s3"
	"github.com/stretchr/testify/assert"
)

func Test_RegoConversion(t *testing.T) {
	s := State{
		AWS: aws.AWS{
			S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: types.NewMetadata(
							types.NewRange("main.tf", 2, 4),
							types.NewNamedReference("aws_s3_bucket.example"),
						),
						Name: types.String("my-bucket", types.NewMetadata(
							types.NewRange("main.tf", 3, 3),
							types.NewNamedReference("aws_s3_bucket.example.bucket"),
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
							"filepath":  "main.tf",
							"startline": 2,
							"endline":   4,
							"managed":   true,
							"explicit":  false,
						},
						"name": map[string]interface{}{
							"filepath":  "main.tf",
							"startline": 3,
							"endline":   3,
							"value":     "my-bucket",
							"managed":   true,
							"explicit":  false,
						},
					},
				},
			},
		},
	}, converted)
}
