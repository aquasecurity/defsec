# METADATA
# title :"Unused Security Groups"
# description: "Identify and remove unused EC2 security groups."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: unused-security-groups 
#   recommended_action: "Remove security groups that are not being used."
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
#            var groups = describeSecurityGroups.data;
#            var usedGroups = helpers.getUsedSecurityGroups(cache, results, region);
#            if (usedGroups && usedGroups.length && usedGroups[0] === 'Error') return rcb();
#            for (var g in groups) {
#                var resource = 'arn:aws:ec2:' + region + ':' + groups[g].OwnerId + ':security-group/' +
#                               groups[g].GroupId;      
#                if (groups[g].GroupId && usedGroups && usedGroups.includes(groups[g].GroupId)) {
#                    helpers.addResult(results, 0, 'Security group is being used', region, resource);
#                } else {
#                    helpers.addResult(results, 2, 'Security group is not being used', region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }