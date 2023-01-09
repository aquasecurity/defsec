# METADATA
# title :"Users Password Last Used"
# description: "Detects users with password logins that have not been used for a period of time and that should be decommissioned"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_admin-change-user.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: users-password-last-used 
#   recommended_action: "Delete old user accounts that allow password-based logins and have not been used recently."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            users_password_last_used_fail: settings.users_password_last_used_fail || this.settings.users_password_last_used_fail.default,
#            users_password_last_used_warn: settings.users_password_last_used_warn || this.settings.users_password_last_used_warn.default
#        };
#
#        var custom = helpers.isCustom(settings, this.settings);
#
#        var results = [];
#        var source = {};
#        
#        var region =  helpers.defaultRegion(settings);
#
#        var generateCredentialReport = helpers.addSource(cache, source,
#            ['iam', 'generateCredentialReport', region]);
#
#        if (!generateCredentialReport) return callback(null, results, source);
#
#        if (generateCredentialReport.err || !generateCredentialReport.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for user password status: ' + helpers.addError(generateCredentialReport));
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
#            var daysAgo;
#            var returnMsg;
#            if (obj.password_last_used && obj.password_last_used !== 'no_information') {
#                daysAgo = helpers.daysAgo(obj.password_last_used);
#
#                returnMsg = 'User password login was last used ' +
#                    daysAgo + ' days ago';
#            } else if (obj.user_creation_time) {
#                // Password is enabled but never used,
#                // find when account was created
#                daysAgo = helpers.daysAgo(obj.user_creation_time);
#
#                returnMsg = 'User was created ' +
#                    daysAgo + ' days ago but password login was never used';
#            } else {
#                // Not enough info in data response
#                continue;
#            }
#
#            var returnCode = 0;
#            if (daysAgo > config.users_password_last_used_fail) {
#                returnCode = 2;
#            } else if (daysAgo > config.users_password_last_used_warn) {
#                returnCode = 1;
#            }
#
#            helpers.addResult(results, returnCode, returnMsg, 'global', obj.arn, custom);
#
#            found = true;
#        }
#
#        if (!found) {
#            helpers.addResult(results, 0, 'No users with password logins found');
#        }
#
#        callback(null, results, source);
#    }