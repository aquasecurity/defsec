
Passing unknown or invalid headers through to the target poses a potential risk of compromise. 

By setting drop_invalid_header_fields to true, anything that doe not conform to well known, defined headers will be removed by the load balancer.

### Impact
Invalid headers being passed through to the target of the load balance may exploit vulnerabilities

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html


