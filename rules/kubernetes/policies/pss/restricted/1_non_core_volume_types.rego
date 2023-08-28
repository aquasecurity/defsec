# METADATA
# title: "Non-core volume types used."
# description: "According to pod security standard 'Volume types', non-core volume types must not be used."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
# custom:
#   id: KSV028
#   avd_id: AVD-KSV-0028
#   severity: LOW
#   short_code: no-non-ephemeral-volumes
#   recommended_action: "Do not Set 'spec.volumes[*]' to any of the disallowed volume types."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: pod
#         - kind: replicaset
#         - kind: replicationcontroller
#         - kind: deployment
#         - kind: statefulset
#         - kind: daemonset
#         - kind: cronjob
#         - kind: job
package builtin.kubernetes.KSV028

import data.lib.kubernetes
import data.lib.utils

# Add disallowed volume type
disallowed_volume_types = [
	"gcePersistentDisk",
	"awsElasticBlockStore",
	# "hostPath", Baseline detects spec.volumes[*].hostPath
	"gitRepo",
	"nfs",
	"iscsi",
	"glusterfs",
	"rbd",
	"flexVolume",
	"cinder",
	"cephFS",
	"flocker",
	"fc",
	"azureFile",
	"vsphereVolume",
	"quobyte",
	"azureDisk",
	"portworxVolume",
	"scaleIO",
	"storageos",
	"csi",
]

# getDisallowedVolumes returns a list of volume names
# which set volume type to any of the disallowed volume types
getDisallowedVolumes[name] {
	volume := kubernetes.volumes[_]
	type := disallowed_volume_types[_]
	utils.has_key(volume, type)
	name := volume.name
}

# failVolumeTypes is true if any of volume has a disallowed
# volume type
failVolumeTypes {
	count(getDisallowedVolumes) > 0
}

deny[res] {
	failVolumeTypes
	msg := kubernetes.format(sprintf("%s '%s' should set 'spec.volumes[*]' to type 'PersistentVolumeClaim'", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, input.spec)
}
