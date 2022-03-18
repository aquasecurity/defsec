
Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.

### Impact
<!-- Add Impact here -->

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.docker.com/develop/develop-images/dockerfile_best-practices/


