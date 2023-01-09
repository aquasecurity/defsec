# METADATA
# title :"Open RFC 1918"
# description: "Ensures EC2 security groups are configured to deny inbound traffic from RFC-1918 CIDRs"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Subnets.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: security-group-rfc1918 
#   recommended_action: "Modify the security group to deny private reserved addresses for inbound traffic"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#
#        var private_cidrs = settings.private_cidrs || this.settings.private_cidrs.default;
#        private_cidrs = private_cidrs.split(',');
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
#                helpers.addResult(results, 0, 'No security groups found', region);
#                return rcb();
#            }
#
#            for (var g in describeSecurityGroups.data) {
#                var group = describeSecurityGroups.data[g];
#                var resource = 'arn:' + awsOrGov + ':ec2:' + region + ':' + group.OwnerId + ':security-group/' + group.GroupId;
#                var privateCidrsFound = [];
#
#                if (!group.IpPermissions || !group.IpPermissions.length) {
#                    helpers.addResult(results, 0,
#                        'Security group :' + group.GroupName + ': does not have any IP permissions', region, resource);
#                    continue;
#                }
#
#                for (var p in group.IpPermissions) {
#                    var permission = group.IpPermissions[p];
#
#                    for (var r in permission.IpRanges) {
#                        var cidrIp = permission.IpRanges[r].CidrIp;
#                      
#                        if (cidrIp && private_cidrs.includes(cidrIp)) {
#                            if (!privateCidrsFound.includes(cidrIp)) {
#                                privateCidrsFound.push(cidrIp);
#                            }
#                        }
#                    }
#
#                    if (!privateCidrsFound.length) {
#                        helpers.addResult(results, 0,
#                            'Security group "' + group.GroupName + '" is not configured to allow traffic from any reserved private addresses',
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            'Security group "' + group.GroupName + '" is configured to allow inbound access for these reserved private addresses: ' + privateCidrsFound.join(', '), 
#                            region, resource);
#                    }
#                }
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    
#    }