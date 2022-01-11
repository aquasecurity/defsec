
Reconsider the use of an public IP

```hcl
resource "opc_compute_ip_address_reservation" "good_example" {
  name            = "my-ip-address"
  ip_address_pool = "cloud-ippool"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/opc/latest/docs/resources/opc_compute_ip_address_reservation
 - https://registry.terraform.io/providers/hashicorp/opc/latest/docs/resources/opc_compute_instance
        