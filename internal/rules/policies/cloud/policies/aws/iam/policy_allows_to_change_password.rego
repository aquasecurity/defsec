# METADATA
# title :"Password Policy Allows To Change Password"
# description: "Ensure IAM password policy allows users to change their passwords."
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
#   short_code: policy-allows-to-change-password 
#   recommended_action: "Update the password policy for users to change their passwords"
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
#        var getAccountPasswordPolicy = helpers.addSource(cache, source,
#            ['iam', 'getAccountPasswordPolicy', region]);
#
#        if (!getAccountPasswordPolicy) return callback(null, results, source);
#
#        // Handle special case errors
#        if (getAccountPasswordPolicy.err &&
#            getAccountPasswordPolicy.err.code &&
#            getAccountPasswordPolicy.err.code === 'NoSuchEntity') {
#            helpers.addResult(results, 2, 'Account does not have a password policy');
#            return callback(null, results, source);
#        }
#
#        if (getAccountPasswordPolicy.err || !getAccountPasswordPolicy.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for password policy status: ' + helpers.addError(getAccountPasswordPolicy));
#            return callback(null, results, source);
#        }
#
#        var passwordPolicy = getAccountPasswordPolicy.data;
#
#        if (!passwordPolicy.AllowUsersToChangePassword) {
#            helpers.addResult(results, 2, 'Password policy does not allow users to change their password');
#        } else {
#            helpers.addResult(results, 0, 'Password policy allow users to change their password');
#        }
#
#        callback(null, results, source);
#    }