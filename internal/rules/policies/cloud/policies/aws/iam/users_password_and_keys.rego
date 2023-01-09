# METADATA
# title :"Users Password And Keys"
# description: "Detects whether users with a console password are also using access keys"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: users-password-and-keys 
#   recommended_action: "Remove access keys from all users with console access."
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
#        try {
#            var machineUsernameRegex = RegExp(settings.iam_machine_username_regex || this.settings.iam_machine_username_regex.default);
#        } catch (err) {
#            helpers.addResult(results, 3, 'Invalid regex for machine username: ' + machineUsernameRegex, 'global');
#        }
#
#        var generateCredentialReport = helpers.addSource(cache, source, ['iam', 'generateCredentialReport', region]);
#
#        if (!generateCredentialReport) return callback(null, results, source);
#
#        if (generateCredentialReport.err || !generateCredentialReport.data) {
#            helpers.addResult(results, 3, 'Unable to query for users: ' + helpers.addError(generateCredentialReport));
#            return callback(null, results, source);
#        }
#
#        if (generateCredentialReport.data.length === 1) {
#            helpers.addResult(results, 0, 'No users with console access found');
#            return callback(null, results, source);
#        }
#
#        var found = false;
#
#        async.each(generateCredentialReport.data, function(obj, cb){
#            // The root account security is handled in a different plugin
#            if (obj.user === '<root_account>') return cb();
#            if (!machineUsernameRegex.test(obj.user)) return cb();
#            if (!obj.password_enabled) return cb();
#
#            found = true;
#
#            if (obj.access_key_1_active || obj.access_key_2_active) {
#                helpers.addResult(results, 2, 'User has console access and access key', 'global', obj.arn);
#            } else {
#                helpers.addResult(results, 0, 'User has console access and no access keys', 'global', obj.arn);
#            }
#
#            cb();
#        }, function(){
#            if (!found) {
#                helpers.addResult(results, 0, 'No users with console access and access keys found');
#            }
#
#            callback(null, results, source);
#        });
#    }