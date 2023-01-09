# METADATA
# title :"Root Account Active Signing Certificates"
# description: "Ensures the root user is not using x509 signing certificates"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/whitepapers/latest/aws-overview-security-processes/x.509-certificates.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: root-signing-certificate 
#   recommended_action: "Delete the x509 certificates associated with the root account."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#
#        var region = helpers.defaultRegion(settings);
#
#        var generateCredentialReport = helpers.addSource(cache, source,
#            ['iam', 'generateCredentialReport', region]);
#        
#        if (!generateCredentialReport) return callback(null, results, source);
#
#        if (generateCredentialReport.err || !generateCredentialReport.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for root user: ' + helpers.addError(generateCredentialReport));
#            return callback(null, results, source);
#        }
#
#        var found = false;
#        for (var r in generateCredentialReport.data) {
#            var obj = generateCredentialReport.data[r];
#            const resource = obj.arn;
#
#            if (obj && obj.user && obj.user === '<root_account>') {
#                found = true;
#
#                if (obj.cert_1_active ||
#                    obj.cert_2_active) {
#                    helpers.addResult(results, 2, 'The root user uses x509 signing certificates.', 'global', resource);
#                } else {
#                    helpers.addResult(results, 0, 'The root user does not use x509 signing certificates.', 'global', resource);
#                }
#
#                break;
#            }
#        }
#
#        if (!found) {
#            helpers.addResult(results, 3, 'Unable to query for root user');
#        }
#
#        callback(null, results, source);
#    }