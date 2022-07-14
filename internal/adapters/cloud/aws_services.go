package cloud

import (
	_ "github.com/aquasecurity/defsec/internal/adapters/cloud/aws/api-gateway"
	_ "github.com/aquasecurity/defsec/internal/adapters/cloud/aws/ec2"
	_ "github.com/aquasecurity/defsec/internal/adapters/cloud/aws/ecr"
	_ "github.com/aquasecurity/defsec/internal/adapters/cloud/aws/ecs"
	_ "github.com/aquasecurity/defsec/internal/adapters/cloud/aws/eks"
	_ "github.com/aquasecurity/defsec/internal/adapters/cloud/aws/iam"
	_ "github.com/aquasecurity/defsec/internal/adapters/cloud/aws/lambda"
	_ "github.com/aquasecurity/defsec/internal/adapters/cloud/aws/s3"
	_ "github.com/aquasecurity/defsec/internal/adapters/cloud/aws/sns"
	_ "github.com/aquasecurity/defsec/internal/adapters/cloud/aws/sqs"
)
