---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/kms_crypto_key#rotation_period"
---

Set key rotation period to 90 days

```hcl
resource "google_kms_key_ring" "keyring" {
   name     = "keyring-example"
   location = "global"
 }
 
 resource "google_kms_crypto_key" "example-key" {
   name            = "crypto-key-example"
   key_ring        = google_kms_key_ring.keyring.id
   rotation_period = "7776000s"
 
   lifecycle {
     prevent_destroy = true
   }
 }
```
