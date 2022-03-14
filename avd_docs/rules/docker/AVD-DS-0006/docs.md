
### COPY '--from' referring to the current image
COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself.

### Impact
<!-- Add Impact here -->

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.docker.com/develop/develop-images/multistage-build/

