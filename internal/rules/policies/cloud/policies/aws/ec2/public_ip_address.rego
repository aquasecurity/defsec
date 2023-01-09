# METADATA
# title :"Public IP Address EC2 Instances"
# description: "Ensures that EC2 instances do not have public IP address attached."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: public-ip-address 
#   recommended_action: "Remove the public IP address from the EC2 instances to block public access to the instance"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        async.each(regions.ec2, function(region, rcb){
#            var describeInstances = helpers.addSource(cache, source,
#                ['ec2', 'describeInstances', region]);
#
#            if (!describeInstances) return rcb();
#
#            if (describeInstances.err || !describeInstances.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for EC2 instances: ${helpers.addError(describeInstances)}`,
#                    region);
#                return rcb();
#            }
#
#            if (!describeInstances.data.length) {
#                helpers.addResult(results, 0, 'No EC2 instances found', region);
#                return rcb();
#            }
#
#            var describeSecurityGroups = helpers.addSource(cache, source,
#                ['ec2', 'describeSecurityGroups', region]);
#
#            if (!describeSecurityGroups || describeSecurityGroups.err || !describeSecurityGroups.data) {
#                helpers.addResult(results, 3, `Unable to query security groups: ${helpers.addError(describeSecurityGroups)}`, region);
#                return rcb();
#            }
#
#            var openSgs = [];
#
#            for (var group of describeSecurityGroups.data) {
#                for (var permissions of group.IpPermissions) {
#                    for (var range of permissions.IpRanges) {
#                        if (range.CidrIp === '0.0.0.0/0') openSgs.push(group.GroupId);
#                    }
#                    for (var v6range of permissions.Ipv6Ranges) {
#                        if (v6range.CidrIpv6 === '::/0') openSgs.push(group.GroupId);
#                    }
#                }
#            }
#
#            describeInstances.data.forEach(function(instance){
#                if (!instance.Instances || !instance.Instances.length) {
#                    helpers.addResult(results, 0, 
#                        'EC2 instance description is not found', region);
#                    return;
#                }
#
#                instance.Instances.forEach(function(element){
#                    var resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:/instance/${element.InstanceId}`;
#                    var openSg = false;
#                    for (var sg of element.SecurityGroups) {
#                        if (openSgs.includes(sg.GroupId)) openSg = true;
#                    }
#
#                    if (element.PublicIpAddress && element.PublicIpAddress.length && openSg) {
#                        helpers.addResult(results, 2,
#                            `EC2 instance "${element.InstanceId}" has a public IP address attached`,
#                            region, resource);
#                    } else if (element.PublicIpAddress && element.PublicIpAddress.length && !openSg) {
#                        helpers.addResult(results, 0,
#                            `EC2 instance "${element.InstanceId}" has a public IP address attached but attached security group is not open to public`,
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 0,
#                            `EC2 instance "${element.InstanceId}" does not have a public IP address attached`,
#                            region, resource);
#                    }
#                });
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }