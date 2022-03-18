
You should use COPY instead of ADD unless you want to extract a tar file. Note that an ADD command will extract a tar file, which adds the risk of Zip-based vulnerabilities. Accordingly, it is advised to use a COPY command, which does not extract tar files.

### Impact
<!-- Add Impact here -->

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.docker.com/engine/reference/builder/#add


