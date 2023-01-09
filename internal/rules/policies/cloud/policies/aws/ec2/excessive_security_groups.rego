# METADATA
# title :"Excessive Security Groups"
# description: "Determine if there are an excessive number of security groups in the account"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: excessive-security-groups 
#   recommended_action: "Limit the number of security groups to prevent accidental authorizations"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            excessive_security_groups_fail: settings.excessive_security_groups_fail || this.settings.excessive_security_groups_fail.default,
#            excessive_security_groups_warn: settings.excessive_security_groups_warn || this.settings.excessive_security_groups_warn.default
#        };
#
#        var custom = helpers.isCustom(settings, this.settings);
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.ec2, function(region, rcb){
#
#            var describeSecurityGroups = helpers.addSource(cache, source,
#                ['ec2', 'describeSecurityGroups', region]);
#            
#            if (!describeSecurityGroups) return rcb();
#
#            if (describeSecurityGroups.err || !describeSecurityGroups.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for security groups: ' + helpers.addError(describeSecurityGroups), region);
#                return rcb();
#            }
#
#            if (!describeSecurityGroups.data.length) {
#                helpers.addResult(results, 0, 'No security groups present', region);
#                return rcb();
#            }
#
#            var returnMsg = ' number of security groups: ' + describeSecurityGroups.data.length + ' groups present';
#
#            if (describeSecurityGroups.data.length > config.excessive_security_groups_fail) {
#                helpers.addResult(results, 2, 'Excessive' + returnMsg, region, null, custom);
#            } else if (describeSecurityGroups.data.length > config.excessive_security_groups_warn) {
#                helpers.addResult(results, 1, 'Large' + returnMsg, region, null, custom);
#            } else {
#                helpers.addResult(results, 0, 'Acceptable' + returnMsg, region, null, custom);
#            }
#
#            rcb();
#            
#        }, function(){
#            callback(null, results, source);
#        });
#    }