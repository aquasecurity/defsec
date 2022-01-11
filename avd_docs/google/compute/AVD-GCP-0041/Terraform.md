
Enable Shielded VM VTPM

```hcl
resource "google_compute_instance" "bad_example" {
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
  
  shielded_instance_config {
    enable_vtpm = true
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#enable_vtpm
        