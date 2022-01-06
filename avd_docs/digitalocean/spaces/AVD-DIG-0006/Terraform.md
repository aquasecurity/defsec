---
additional_links: 
  - "https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket#acl"
  - "https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket_object#acl"
---

Apply a more restrictive ACL

```hcl
resource "digitalocean_spaces_bucket" "good_example" {
   name   = "private_space"
   region = "nyc3"
   acl    = "private"
 }
   
 resource "digitalocean_spaces_bucket_object" "index" {
   region       = digitalocean_spaces_bucket.good_example.region
   bucket       = digitalocean_spaces_bucket.good_example.name
   key          = "index.html"
   content      = "<html><body><p>This page is empty.</p></body></html>"
   content_type = "text/html"
 }
```
