# METADATA
# custom:
#   input:
#     selector:
#     - type: kubernetes
#     - type: rbac
package lib.utils

has_key(x, k) {
	_ = x[k]
}
