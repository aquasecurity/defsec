# METADATA
# title :"Canary Keys Used"
# description: "Detects when a special canary-token access key has been used"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: canary-keys-used 
#   recommended_action: "Create a canary access token and provide its user to CloudSploit. If CloudSploit detects that the account is in use, it will trigger a failure."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            canary_user: settings.canary_user || this.settings.canary_user.default
#        };
#
#        var results = [];
#        var source = {};
#
#        var region = helpers.defaultRegion(settings);
#
#        if (!config.canary_user ||
#            !config.canary_user.length) return callback(null, results, source);
#
#        var generateCredentialReport = helpers.addSource(cache, source,
#            ['iam', 'generateCredentialReport', region]);
#
#        if (!generateCredentialReport) return callback(null, results, source);
#
#        if (generateCredentialReport.err || !generateCredentialReport.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for users: ' + helpers.addError(generateCredentialReport));
#            return callback(null, results, source);
#        }
#
#        if (generateCredentialReport.data.length <= 2) {
#            helpers.addResult(results, 0, 'No users using access keys found');
#            return callback(null, results, source);
#        }
#
#        var found = false;
#
#        async.each(generateCredentialReport.data, function(obj, cb){
#            // The root account security is handled in a different plugin
#            if (obj.user !== config.canary_user) return cb();
#            found = true;
#
#            if (obj.access_key_1_last_used_date ||
#                obj.access_key_2_last_used_date) {
#                helpers.addResult(results, 2, 'The canary user: ' + config.canary_user + ' has been used.');
#            } else {
#                helpers.addResult(results, 0, 'The canary user: ' + config.canary_user + ' has not been used.');
#            }
#
#            cb();
#        }, function(){
#            if (!found) {
#                helpers.addResult(results, 3, 'The canary user specified in the config could not be found.');
#            }
#
#            callback(null, results, source);
#        });
#    }