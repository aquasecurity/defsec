# METADATA
# title :"Access Keys Extra"
# description: "Detects the use of more than one access key by any single user"
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
#   short_code: access-keys-extra 
#   recommended_action: "Remove the extra access key for the specified user."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
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
#        if (generateCredentialReport.data.length <= 2) {
#            helpers.addResult(results, 0, 'No users using access keys found');
#            return callback(null, results, source);
#        }
#
#        var found = false;
#
#        async.each(generateCredentialReport.data, function(obj, cb){
#            // The root account security is handled in a different plugin
#            if (obj.user === '<root_account>') return cb();
#
#            if (obj.access_key_1_active && obj.access_key_2_active) {
#                helpers.addResult(results, 2, 'User is using both access keys', 'global', obj.arn);
#            } else {
#                helpers.addResult(results, 0, 'User is not using both access keys', 'global', obj.arn);
#            }
#
#            found = true;
#
#            cb();
#        }, function(){
#            if (!found) {
#                helpers.addResult(results, 0, 'No users using both access keys found');
#            }
#
#            callback(null, results, source);
#        });
#    }