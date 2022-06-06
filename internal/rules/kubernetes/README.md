## Comprehensive REGO library for Kubernetes workload configuration checks

Examples:
- Use our REGO policies with tools such as OPA Gatekeeper and Conftest to check kubernetes resources configurations
- Ensure pods and controllers are not running as privileged
- Ensure pods images are hosted in a trusted ECR/GCR/ACR registry
- And more checks to comply with PSP, PSS and additional standards

# Quick start
Follow these steps to pull a policy and test Kubernetes workload manifest:

1. Create a directory named "myPolicy" to host all the required rego checks

```
mkdir myPolicy
```
2. Download the main library and the desired checks(s) into "myPolicy" directory - in this example we use the "host_ipc" check only
```
wget https://github.com/aquasecurity/defsec/raw/master/internal/rules/kubernetes/lib/kubernetes.rego
wget https://github.com/aquasecurity/defsec/raw/master/internal/rules/kubernetes/lib/utils.rego
wget https://github.com/aquasecurity/defsec/raw/master/internal/rules/defsec/lib/defsec.rego
wget https://github.com/aquasecurity/defsec/raw/master/internal/rules/kubernetes/policies/pss/baseline/1_host_ipc.rego
```
3. Download an example of a non-compliant kubernetes deployment (in yaml format) 
```
wget https://github.com/aquasecurity/defsec/raw/master/test/testdata/kubernetes/KSV008/denied.yaml
```
4. Use any tool that supports REGO to test the example file. In this example we are using conftest
```
conftest test denied.yaml --policy myPolicy/ --namespace builtin.kubernetes.KSV008
```

# Standards and best practices
This GitHub repository has controls that cover both [PodSecurityPolicy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/) (PSP) and the Kubernetes [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) (PSS), plus additional best practices.

## PSS and PSP
The Kubernetes Pod Security Standards (PSS) are the official standard for security best practices for pods. These standards overlaps with the checks that PodSecurityPolicies can enforce.

PSS has 14 controls that are grouped into three standards: Baseline, Restricted and Privileged. Appshield uses Baseline and Restricted; the Privileged standard specifically allows privileged execution. We named the controls in this repository under the PSS controls because they are more up-to-date and have better coverage than PSP. The below table maps PSS controls to PSP controls:

### PSS - Baseline

| PSS control             | PSP control(s)                                                   |
|-------------------------|------------------------------------------------------------------|
 | 1-Host Namespaces       | 2-Usage of host namespaces. 3-Usage of host networking and ports |
 | 2-Privileged Containers | 	1-Running of privileged containers                              |
 | 3-Capabilities          | 11-Linux capabilities                                            |
 | 4-HostPath Volumes      | 5-Usage of the host filesystem                                   |
 | 5-Host Ports            | Not covered in PSP                                               |
 | 6-AppArmor (optional)	  | 14-The AppArmor profile used by containers                       |
 | 7-SELinux (optional)	   | 12-The SELinux context of the container                          |
 | 8-/proc Mount Type	     | 13-The Allowed Proc Mount types for the container                |
 | 9-Sysctls	              | 16-The sysctl profile used by containers                         |

The REGO rules are available [here](https://github.com/aquasecurity/defsec/tree/master/internal/rules/kubernetes/policies/pss)

### PSS - Restricted

| PSS control             | PSP control                                                                                                      |
|:------------------------|:-----------------------------------------------------------------------------------------------------------------|
 | 1-Volume Types          | 4-Usage of volume types 6-Allow specific FlexVolume drivers. 8-Requiring the use of a read-only root file system |
 | 2-Privilege Escalation  | 10-Restricting escalation to root privileges                                                                     |
 | 3-Running as Non-root   | Not covered in PSP                                                                                               |
 | 4-Non-root groups       | 7-Allocating an FSGroup that owns the Pod's volumes. 9-The user and group IDs of the container                   |
 | 5-Seccomp               | 15-The seccomp profile used by containers                                                                        |

The REGO rules are available [here](https://github.com/aquasecurity/defsec/tree/master/internal/rules/kubernetes/policies/pss)

## Optional best practices

Top Examples:

| Best practice                            | tested field in the manifest                   |
|:-----------------------------------------|:-----------------------------------------------|
| Trust ECR registries only                | container(s).image != ECR domain in prefix     |  
| Trust ACR registries only                | container(s).image != ACR domain in prefix     |
| Trust GCR registries only                | container(s).image != GCR domain in prefix     | 
| Block public registries                  | container(s).image != null or docker.io prefix |
| HostPath volume mounted with docker.sock | hostPath.path != /var/run/docker.sock          |

Additional REGO rules available [here](https://github.com/aquasecurity/defsec/tree/master/internal/rules/kubernetes/policies/advanced/optional)
