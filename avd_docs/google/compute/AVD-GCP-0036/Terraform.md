
Enable OS Login at project level and remove instance-level overrides

```hcl
 resource "google_compute_instance" "default" {
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
 
   metadata = {
   }
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#

