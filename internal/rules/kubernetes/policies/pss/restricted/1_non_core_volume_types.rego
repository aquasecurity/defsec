# METADATA
# title: "Non-ephemeral volume types used"
# description: "In addition to restricting HostPath volumes, usage of non-ephemeral volume types should be limited to those defined through PersistentVolumes."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KSV028
#   avd_id: AVD-KSV-0028
#   severity: LOW
#   short_code: no-non-ephemeral-volumes
#   recommended_action: "Do not Set 'spec.volumes[*]' to any of the disallowed volume types."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV028

import data.lib.kubernetes
import data.lib.result
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
