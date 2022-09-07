
Set node metadata to SECURE or GKE_METADATA_SERVER

```hcl
 resource "google_container_node_pool" "good_example" {
 	node_config {
 		workload_metadata_config {
 			node_metadata = "SECURE"
 		}
 	}
 }
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#node_metadata

