---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#can_ip_forward"
---

Disable IP forwarding

```hcl
resource "google_compute_instance" "bad_example" {
   name         = "test"
   machine_type = "e2-medium"
   zone         = "us-central1-a"
 
   boot_disk {
     initialize_params {
       image = "debian-cloud/debian-9"
     }
   }
 
   // Local SSD disk
   scratch_disk {
     interface = "SCSI"
   }
   
   can_ip_forward = false
 }
```
