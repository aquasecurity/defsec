# METADATA
# title :"Password Reuse Prevention"
# description: "Ensures password policy prevents previous password reuse"
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
#   short_code: password-reuse-prevention 
#   recommended_action: "Increase the minimum previous passwords that can be reused to 24."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            password_reuse_fail: settings.password_reuse_fail || this.settings.password_reuse_fail.default,
#            password_reuse_warn: settings.password_reuse_warn || this.settings.password_reuse_warn.default
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
#        if (!passwordPolicy.PasswordReusePrevention) {
#            helpers.addResult(results, 2, 'Password policy does not prevent reusing previous passwords');
#        } else if (passwordPolicy.PasswordReusePrevention < config.password_reuse_fail) {
#            helpers.addResult(results, 2,
#                'Maximum password reuse of: ' + passwordPolicy.PasswordReusePrevention + ' passwords is less than ' + config.password_reuse_fail, 'global', null, custom);
#        } else if (passwordPolicy.PasswordReusePrevention < config.password_reuse_warn) {
#            helpers.addResult(results, 1,
#                'Maximum password reuse of: ' + passwordPolicy.PasswordReusePrevention + ' passwords is less than ' + config.password_reuse_warn, 'global', null, custom);
#        } else {
#            helpers.addResult(results, 0,
#                'Maximum password reuse of: ' + passwordPolicy.PasswordReusePrevention + ' passwords is suitable', 'global', null, custom);
#        }
#
#        callback(null, results, source);
#    }