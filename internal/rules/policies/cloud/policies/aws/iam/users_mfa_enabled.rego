# METADATA
# title :"Users MFA Enabled"
# description: "Ensures a multi-factor authentication device is enabled for all users within the account"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: users-mfa-enabled 
#   recommended_action: "Enable an MFA device for the user account"
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
#                'Unable to query for user MFA status: ' + helpers.addError(generateCredentialReport));
#            return callback(null, results, source);
#        }
#
#        if (generateCredentialReport.data.length === 1) {
#            // Only have the root user
#            helpers.addResult(results, 0, 'No user accounts found');
#            return callback(null, results, source);
#        }
#
#        var found = false;
#
#        for (var r in generateCredentialReport.data) {
#            var obj = generateCredentialReport.data[r];
#
#            // Skip root user and users without passwords
#            // since they won't be logging into the console
#            if (obj.user === '<root_account>') continue;
#            if (!obj.password_enabled) continue;
#
#            found = true;
#
#            if (obj.mfa_active) {
#                helpers.addResult(results, 0,
#                    'User: ' + obj.user + ' has an MFA device', 'global', obj.arn);
#            } else {
#                helpers.addResult(results, 2,
#                    'User: ' + obj.user + ' does not have an MFA device enabled', 'global', obj.arn);
#            }
#        }
#
#        if (!found) {
#            helpers.addResult(results, 0, 'No users with passwords requiring MFA found');
#        }
#
#        callback(null, results, source);
#    }