# METADATA
# title :"Default Security Group"
# description: "Ensure the default security groups block all traffic by default"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html#default-security-group
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: default-security-group 
#   recommended_action: "Update the rules for the default security group to deny all traffic by default"
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
#            for (var s in describeSecurityGroups.data) {
#                var sg = describeSecurityGroups.data[s];
#                // arn:aws:ec2:region:account-id:security-group/security-group-id
#                var resource = 'arn:aws:ec2:' + region + ':' + sg.OwnerId + ':security-group/' + sg.GroupId;
#
#                if (sg.GroupName === 'default') {
#                    if (sg.IpPermissions.length ||
#                         sg.IpPermissionsEgress.length) {
#                        helpers.addResult(results, 2,
#                            'Default security group has ' + (sg.IpPermissions.length || '0') + ' inbound and ' + (sg.IpPermissionsEgress.length || '0') + ' outbound rules',
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 0,
#                            'Default security group does not have inbound or outbound rules',
#                            region, resource);
#                    }
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }