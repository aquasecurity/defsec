---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#access_config"
---

Remove public IP

```hcl
resource "google_compute_instance" "good_example" {
   name         = "test"
   machine_type = "e2-medium"
   zone         = "us-central1-a"
 
   tags = ["foo", "bar"]
 
   boot_disk {
     initialize_params {
       image = "debian-cloud/debian-9"
     }
   }
 
   // Local SSD disk
   scratch_disk {
     interface = "SCSI"
   }
 
   network_interface {
     network = "default"
   }
 }
```
