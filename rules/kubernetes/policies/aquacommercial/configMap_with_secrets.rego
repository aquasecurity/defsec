# METADATA
# title: "ConfigMap with secrets"
# description: "Storing secrets in configMaps is unsafe"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# custom:
#   id: AVD-KSV-0109
#   avd_id: AVD-KSV-0109
#   severity: HIGH
#   short_code: configMap_with_secrets
#   recommended_action: "Remove password/secret from configMap data value"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: configmap

package builtin.kubernetes.KSV0109


import data.lib.kubernetes

# More patterns can be added here, adding more patterns may lead to performance issue
patterns := [
	"(?i)(password\\s*(=|:))",
	"(?i)(pw\\s*(=|:))",
	"(?i)(pass\\s*(=|:))",
	"(?i)(pword\\s*(=|:))",
	"(?i)(passphrase\\s*(=|:))",
	"(?i)(passwrd\\s*(=|:))",
	"(?i)(passwd\\s*(=|:))",
	"(?i)(secret\\s*(=|:))",
	"(?i)(secretkey\\s*(=|:))",
	"(?i)(appSecret\\s*(=|:))",
	"(?i)(clientSecret\\s*(=|:))",
	"(?i)(aws_access_key_id\\s*(=|:))",
	"(?i)(pswrd\\s*(=|:))",
	"(?i)(token\\s*(=|:))",
	"(?i)(pwd\\s*(=|:))",
]

#Added patterns for detecting secrets in key
patternsForKey := [
	"(?i)(password\\s*)",
	"(?i)(pw\\s*)",
	"(?i)(pass\\s*)",
	"(?i)(pword\\s*)",
	"(?i)(passphrase\\s*)",
	"(?i)(passwrd\\s*)",
	"(?i)(passwd\\s*)",
	"(?i)(secret\\s*)",
	"(?i)(secretkey\\s*)",
	"(?i)(appSecret\\s*)",
	"(?i)(clientSecret\\s*)",
	"(?i)(aws_access_key_id\\s*)",
	"(?i)(pswrd\\s*)",
	"(?i)(token\\s*)",
	"(?i)(pwd\\s*)",
]

# ConfigMapWithSecret gives secret key
# To reduce performance overhead, only matched patterns will be applied to each value for key
ConfigMapWithSecret[secrets] {
	kubernetes.kind == "ConfigMap"
	regex.match(patterns[p], kubernetes.object.data[d])

	values := split(kubernetes.object.data[d], "\n")
	regex.match(patterns[p], values[v])
	secrets = configMapValue(values[v])
}

# configMapValue gives secret key, splitting either by '=' or ':'
configMapValue(value) = secretValue {
	secrets := split(value, ":")
	count(secrets) > 1
	secretValue = secrets[0]
} else = secretValue {
	secrets := split(value, "=")
	count(secrets) > 1
	secretValue = secrets[0]
}

#check if key has secrets
ConfigMapWithSecret[secrets] {
	kubernetes.kind == "ConfigMap"
	values = split(kubernetes.object.data[d], "\n")
	regex.match(patternsForKey[p], d)
	secrets = d
}

# Get the secret list, 'configMapSecretList' will be reused in rule deny to avoid multiple call for pattern search
configMapSecretList := ConfigMapWithSecret

deny[res] {
	count(configMapSecretList) > 0
	msg := kubernetes.format(sprintf("%s '%s' in '%s' namespace stores secrets in key(s) or value(s) '%s'", [kubernetes.kind, kubernetes.name, kubernetes.namespace, configMapSecretList]))
	res := result.new(msg, kubernetes.kind)
}
