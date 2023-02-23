package elastictranscoder

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elastictranscoder"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) elastictranscoder.ElasticTranscoder {
	return elastictranscoder.ElasticTranscoder{
		Pipelines: nil,
	}
}
