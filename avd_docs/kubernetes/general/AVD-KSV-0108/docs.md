
Services with external IP addresses allows direct access from the internet and might expose risk for CVE-2020-8554

### Impact
Kubernetes API server in all versions allow an attacker who is able to create a ClusterIP service and set the spec.externalIPs field, to intercept traffic to that IP address. Additionally, an attacker who is able to patch the status (which is considered a privileged operation and should not typically be granted to users) of a LoadBalancer service can set the status.loadBalancer.ingress.ip to similar effect.
https://www.cvedetails.com/cve/CVE-2020-8554/

<!-- DO NOT CHANGE -->
{{ remediationActions }}


