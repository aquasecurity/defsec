---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#raw_key"
---

Use managed keys or provide the raw key via a secrets manager 

```hcl
resource "google_compute_disk" "good_example" {
   name  = "test-disk"
   type  = "pd-ssd"
   zone  = "us-central1-a"
   image = "debian-9-stretch-v20200805"
   labels = {
     environment = "dev"
   }
   physical_block_size_bytes = 4096
 }
```
