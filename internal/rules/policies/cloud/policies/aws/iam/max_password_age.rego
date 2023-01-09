# METADATA
# title :"Maximum Password Age"
# description: "Ensures password policy requires passwords to be reset every 180 days"
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
#   short_code: max-password-age 
#   recommended_action: "Descrease the maximum allowed age of passwords for the password policy"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            max_password_age_fail: settings.max_password_age_fail || this.settings.max_password_age_fail.default,
#            max_password_age_warn: settings.max_password_age_warn || this.settings.max_password_age_warn.default
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
#        if (!passwordPolicy.MaxPasswordAge) {
#            helpers.addResult(results, 2, 'Password policy does not specify a maximum password age');
#        } else if (passwordPolicy.MaxPasswordAge > config.max_password_age_fail) {
#            helpers.addResult(results, 2, `Maximum password age of: ${passwordPolicy.MaxPasswordAge} days is more than ${config.max_password_age_fail}`, 'global', null, custom);
#        } else if (passwordPolicy.MaxPasswordAge > config.max_password_age_warn) {
#            helpers.addResult(results, 1, `Maximum password age of: ${passwordPolicy.MaxPasswordAge} days is more than ${config.max_password_age_warn}`, 'global', null, custom);
#        } else {
#            helpers.addResult(results, 0, `Maximum password age of: ${passwordPolicy.MaxPasswordAge} days is suitable`, 'global', null, custom);
#        }
#
#        callback(null, results, source);
#    }