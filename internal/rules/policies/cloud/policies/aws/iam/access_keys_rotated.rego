# METADATA
# title :"Access Keys Rotated"
# description: "Ensures access keys are not older than 180 days in order to reduce accidental exposures"
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
#   short_code: access-keys-rotated 
#   recommended_action: "To rotate an access key, first create a new key, replace the key and secret throughout your app or scripts, then set the previous key to disabled. Once you ensure that no services are broken, then fully delete the old key."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            access_keys_rotated_fail: settings.access_keys_rotated_fail || this.settings.access_keys_rotated_fail.default,
#            access_keys_rotated_warn: settings.access_keys_rotated_warn || this.settings.access_keys_rotated_warn.default
#        };
#
#        var custom = helpers.isCustom(settings, this.settings);
#
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
#                'Unable to query for users: ' + helpers.addError(generateCredentialReport));
#            return callback(null, results, source);
#        }
#
#        if (generateCredentialReport.data.length == 1) {
#            helpers.addResult(results, 0, 'No IAM user accounts found');
#            return callback(null, results, source);
#        }
#
#        var found = false;
#
#        function addAccessKeyResults(lastRotated, keyNum, arn, userCreationTime) {
#            var returnMsg = 'User access key ' + keyNum + ' ' + ((lastRotated === 'N/A' || !lastRotated) ? 'has never been rotated' : 'was last rotated ' + helpers.daysAgo(lastRotated) + ' days ago');
#
#            if (helpers.daysAgo(userCreationTime) > config.access_keys_rotated_fail &&
#                (!lastRotated || lastRotated === 'N/A' || helpers.daysAgo(lastRotated) > config.access_keys_rotated_fail)) {
#                helpers.addResult(results, 2, returnMsg, 'global', arn, custom);
#            } else if (helpers.daysAgo(userCreationTime) > config.access_keys_rotated_warn &&
#                (!lastRotated || lastRotated === 'N/A' || helpers.daysAgo(lastRotated) > config.access_keys_rotated_warn)) {
#                helpers.addResult(results, 1, returnMsg, 'global', arn, custom);
#            } else {
#                helpers.addResult(results, 0,
#                    'User access key '  + keyNum + ' ' +
#                    ((lastRotated === 'N/A') ? 'has never been rotated but user is only ' + helpers.daysAgo(userCreationTime) + ' days old' : 'was last rotated ' + helpers.daysAgo(lastRotated) + ' days ago'), 'global', arn, custom);
#            }
#
#            found = true;
#        }
#
#        async.each(generateCredentialReport.data, function(obj, cb){
#            // TODO: update to handle booleans
#            // The root account security is handled in a different plugin
#            if (obj.user === '<root_account>') return cb();
#
#            if (obj.access_key_1_active) {
#                addAccessKeyResults(obj.access_key_1_last_rotated, '1', obj.arn + ':access_key_1', obj.user_creation_time);
#            }
#
#            if (obj.access_key_2_active) {
#                addAccessKeyResults(obj.access_key_2_last_rotated, '2', obj.arn + ':access_key_2', obj.user_creation_time);
#            }
#
#            cb();
#        }, function(){
#            if (!found) {
#                helpers.addResult(results, 0, 'No IAM user accounts using access keys found');
#            }
#
#            callback(null, results, source);
#        });
#    }