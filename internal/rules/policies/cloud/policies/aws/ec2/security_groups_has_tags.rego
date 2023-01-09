# METADATA
# title :"Security Group Has Tags"
# description: "Ensure that AWS Security Groups have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://aws.amazon.com/about-aws/whats-new/2021/07/amazon-ec2-adds-resource-identifiers-tags-vpc-security-groups-rules/
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: security-groups-has-tags 
#   recommended_action: "Update Security Group and add Tags"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.ec2, function(region, rcb){
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
#            for (var sg of describeSecurityGroups.data) {
#                const arn = `arn:aws:ec2:${region}:${sg.OwnerId}:security-group/${sg.GroupId}`;
#                if (!sg.Tags || !sg.Tags.length) {
#                    helpers.addResult(results, 2, 'Security group does not have tags', region, arn);
#                } else {
#                    helpers.addResult(results, 0, 'Security group has tags', region, arn);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }