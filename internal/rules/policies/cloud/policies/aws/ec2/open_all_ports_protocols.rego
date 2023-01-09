# METADATA
# title :"Open All Ports Protocols"
# description: "Determine if security group has all ports or protocols open to the public"
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
#   short_code: open-all-ports-protocols 
#   recommended_action: "Modify the security group to specify a specific port and protocol to allow."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            ec2_skip_unused_groups: settings.ec2_skip_unused_groups || this.settings.ec2_skip_unused_groups.default,
#        };
#
#        config.ec2_skip_unused_groups = (config.ec2_skip_unused_groups == 'true');
#        
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
#            if (config.ec2_skip_unused_groups) {
#                var usedGroups = helpers.getUsedSecurityGroups(cache, results, region, rcb);
#            }
#
#            for (var g in groups) {
#                var strings = [];
#                var resource = 'arn:aws:ec2:' + region + ':' +
#                               groups[g].OwnerId + ':security-group/' +
#                               groups[g].GroupId;
#
#                for (var p in groups[g].IpPermissions) {
#                    var permission = groups[g].IpPermissions[p];
#
#                    for (var k in permission.IpRanges) {
#                        var range = permission.IpRanges[k];
#
#                        if (range.CidrIp === '0.0.0.0/0') {
#                            if (!permission.FromPort && (!permission.ToPort || permission.ToPort === 65535)) {
#                                var string = 'all ports open to 0.0.0.0/0';
#                                if (strings.indexOf(string) === -1) strings.push(string);
#                            }
#
#                            if (permission.IpProtocol === '-1') {
#                                var stringO = 'all protocols open to 0.0.0.0/0';
#                                if (strings.indexOf(stringO) === -1) strings.push(stringO);
#                            }
#                        }
#                    }
#
#                    for (var l in permission.Ipv6Ranges) {
#                        var rangeV6 = permission.Ipv6Ranges[l];
#
#                        if (rangeV6.CidrIpv6 === '::/0') {
#                            if (!permission.FromPort && (!permission.ToPort || permission.ToPort === 65535)) {
#                                var stringV6 = 'all ports open to ::/0';
#                                if (strings.indexOf(stringV6) === -1) strings.push(stringV6);
#                            }
#
#                            if (permission.IpProtocol === '-1') {
#                                var stringP = 'all protocols open to ::/0';
#                                if (strings.indexOf(stringP) === -1) strings.push(stringP);
#                            }
#                        }
#                    }
#                }
#
#                if (strings.length) {
#                    if (config.ec2_skip_unused_groups && groups[g].GroupId && !usedGroups.includes(groups[g].GroupId)) {
#                        helpers.addResult(results, 1, `Security Group: ${groups[g].GroupId} is not in use`,
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            'Security group: ' + groups[g].GroupId +
#                            ' (' + groups[g].GroupName +
#                            ') has ' + strings.join(' and '), region,
#                            resource);
#                    }
#                } else {
#                    helpers.addResult(results, 0,
#                        `Security group: ${groups[g].GroupId} (${groups[g].GroupName}) does not have all ports or protocols open to the public`,
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }