# METADATA
# title :"IAM Username Matches Regex"
# description: "Ensures all IAM user names match the given regex"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: iam-user-name-regex 
#   recommended_action: "Rename the IAM user name to match the provided regex."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#
#        var usernameRegex = RegExp(this.settings.iam_username_regex.default);
#        try {
#            usernameRegex = RegExp(settings.iam_username_regex || this.settings.iam_username_regex.default);
#        } catch (err) {
#            helpers.addResult(results, 3, err.message, 'global', this.settings.iam_username_regex.name);
#        }
#
#        var region = helpers.defaultRegion(settings);
#
#        var generateCredentialReport = helpers.addSource(cache, source, ['iam', 'generateCredentialReport', region]);
#
#        if (!generateCredentialReport) {
#            return callback(null, results, source);
#        }
#
#        if (generateCredentialReport.err || !generateCredentialReport.data) {
#            helpers.addResult(results, 3, 'Unable to query for users: ' + helpers.addError(generateCredentialReport));
#            return callback(null, results, source);
#        }
#
#        async.each(generateCredentialReport.data, function(user, cb) {
#            var username = user.user;
#
#            // ignore the root account name
#            if (!username || username === '<root_account>') {
#                helpers.addResult(results, 0, 'Root account', 'global', user.arn);
#                return cb();
#            }
#
#            if (usernameRegex.test(username)) {
#                helpers.addResult(results, 0, 'IAM username matches regex', 'global', user.arn);
#                return cb();
#            }
#
#            helpers.addResult(results, 2, 'IAM username improperly named', 'global', user.arn);
#            return cb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }