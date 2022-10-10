
Encrypt Cloud Storage buckets using customer-managed keys.

```hcl
 resource "google_storage_bucket" "default" {
   name                        = "my-default-bucket"
   location                    = "EU"
   force_destroy               = true
   uniform_bucket_level_access = true

   encryption {
     default_kms_key_name = "projects/my-pet-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key"
   }
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket#encryption

