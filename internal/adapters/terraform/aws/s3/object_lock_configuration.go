package s3

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
)

func (a *adapter) adaptobjectLockConfig() {

	for _, b := range a.modules.GetResourcesByType("aws_s3_bucket_object_lock_configuration") {

		olc := s3.ObjectLockConfiguration{
			Metadata:          b.GetMetadata(),
			ObjectLockEnabled: b.GetAttribute("object_lock_enabled").AsStringValueOrDefault("", b),
		}

		var bucketName string
		bucketAttr := b.GetAttribute("bucket")
		if bucketAttr.IsNotNil() {
			if referencedBlock, err := a.modules.GetReferencedBlock(bucketAttr, b); err == nil {
				if bucket, ok := a.bucketMap[referencedBlock.ID()]; ok {
					bucket.ObjectLockConfiguration = &olc
					a.bucketMap[referencedBlock.ID()] = bucket
					continue
				}
			}
		}
		if bucketAttr.IsString() {
			bucketName = bucketAttr.Value().AsString()
			for id, bucket := range a.bucketMap {
				if bucketAttr.Equals(id) || bucket.Name.EqualTo(bucketName) {
					bucket.ObjectLockConfiguration = &olc
					a.bucketMap[id] = bucket
					continue
				}
			}
		}
	}
}
