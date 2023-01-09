# METADATA
# title :"Minimum Password Length"
# description: "Ensures password policy requires a password of at least a minimum number of characters"
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
#   short_code: min-password-length 
#   recommended_action: "Increase the minimum length requirement for the password policy"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            min_password_length_fail: settings.min_password_length_fail || this.settings.min_password_length_fail.default,
#            min_password_length_warn: settings.min_password_length_warn || this.settings.min_password_length_warn.default
#        };
#
#        var custom = helpers.isCustom(settings, this.settings);
#
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
#        if (!passwordPolicy.MinimumPasswordLength) {
#            helpers.addResult(results, 2, 'Password policy does not specify a minimum password length');
#        } else if (passwordPolicy.MinimumPasswordLength < config.min_password_length_fail) {
#            helpers.addResult(results, 2, `Minimum password length of: ${passwordPolicy.MinimumPasswordLength} is less than ${config.min_password_length_fail} characters`, 'global', null, custom);
#        } else if (passwordPolicy.MinimumPasswordLength < config.min_password_length_warn) {
#            helpers.addResult(results, 1, `Minimum password length of: ${passwordPolicy.MinimumPasswordLength} is less than ${config.min_password_length_warn} characters`, 'global', null, custom);
#        } else {
#            helpers.addResult(results, 0, `Minimum password length of: ${passwordPolicy.MinimumPasswordLength} is suitable`, 'global', null, custom);
#        }
#
#        callback(null, results, source);
#    }