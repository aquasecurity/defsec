# METADATA
# title :"Shield Advanced Enabled"
# description: "Ensures AWS Shield Advanced is setup and properly configured"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/waf/latest/developerguide/ddos-overview.html#ddos-advanced
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Shield
#   severity: LOW
#   short_code: shield-advanced-enabled 
#   recommended_action: "Enable AWS Shield Advanced for the account."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var region = helpers.defaultRegion(settings);
#
#        var describeSubscription = helpers.addSource(cache, source,
#            ['shield', 'describeSubscription', region]);
#
#        if (!describeSubscription) return callback(null, results, source);
#
#        if (describeSubscription.err &&
#            describeSubscription.err.code &&
#            describeSubscription.err.code == 'ResourceNotFoundException') {
#            helpers.addResult(results, 2, 'Shield subscription is not enabled');
#            return callback(null, results, source);
#        }
#
#        if (describeSubscription.err || !describeSubscription.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for Shield subscription: ' + helpers.addError(describeSubscription));
#            return callback(null, results, source);
#        }
#
#        if (!describeSubscription.data.EndTime) {
#            helpers.addResult(results, 2, 'Shield subscription is not enabled');
#            return callback(null, results, source);
#        }
#
#        var end = describeSubscription.data.EndTime;
#        var now = new Date();
#        var renewing = (describeSubscription.data.AutoRenew && describeSubscription.data.AutoRenew == 'ENABLED');
#
#        if (now >= end) {
#            helpers.addResult(results, 2, 'Shield subscription has expired');
#            return callback(null, results, source);
#        }
#
#        var daysBetween = helpers.daysBetween(now, end);
#
#        if (daysBetween <= 90 && !renewing) {
#            helpers.addResult(results, 2, 'Shield subscription is expiring in ' + daysBetween + ' days and is not configured to auto-renew');
#        } else if (!renewing) {
#            helpers.addResult(results, 1, 'Shield subscription is expiring in ' + daysBetween + ' days and is not configured to auto-renew');
#        } else {
#            helpers.addResult(results, 0, 'Shield subscription is enabled, expiring in ' + daysBetween + ' days and is configured to auto-renew');
#        }
#
#        return callback(null, results, source);
#    }