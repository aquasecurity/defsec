# METADATA
# title :"Allowed Custom Ports"
# description: "Ensures that security groups does not allow public access to any port."
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
#   short_code: allowed-custom-ports 
#   recommended_action: "Modify the security group to ensure the ports are not exposed publicly"
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
#        var whitelisted_open_ports = settings.whitelisted_open_ports || this.settings.whitelisted_open_ports.default;
#        
#        if (!whitelisted_open_ports.length) return callback();
#
#        whitelisted_open_ports = whitelisted_open_ports.split(',');
#
#
#        var ports = {};
#        whitelisted_open_ports.forEach(port => {
#            var [protocol, portNo] = port.split(':');
#            if (portNo.indexOf('-') > -1) {
#                var portRange = portNo.split('-');
#                var rangeFrom = portRange[0];
#                var rangeTo = portRange[1];
#                for (var i = rangeFrom; i <= rangeTo; i++) {
#                    if (ports[protocol]) {
#                        ports[protocol].push(Number(i));
#                    } else {
#                        ports[protocol] = [Number(i)];
#                    }
#                }
#            } else {
#                if (ports[protocol]) {
#                    ports[protocol].push(Number(portNo));
#                } else {
#                    ports[protocol] = [Number(portNo)];
#                }
#            }
#        });
#
#        async.each(regions.ec2, function(region, rcb){
#            var describeSecurityGroups = helpers.addSource(cache, source,
#                ['ec2', 'describeSecurityGroups', region]);
#
#            if (!describeSecurityGroups) return rcb();
#
#            if (describeSecurityGroups.err || !describeSecurityGroups.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for security groups: ${helpers.addError(describeSecurityGroups)}`, region);
#                return rcb();
#            }
#
#            if (!describeSecurityGroups.data.length) {
#                helpers.addResult(results, 0, 'No security groups found', region);
#                return rcb();
#            }
#
#            // Loop through each security group
#            for (var g in describeSecurityGroups.data) {
#                var group = describeSecurityGroups.data[g];
#                var resource = `arn:${awsOrGov}:ec2:${region}:${group.OwnerId}:security-group/${group.GroupId}`;
#
#                if (!group.IpPermissions) continue;
#
#                var cidrIps = [];
#
#                // Loop through each ip permissions in a security group
#                IpPermissionsLoop:
#                for (var p in group.IpPermissions) {
#                    var permission = group.IpPermissions[p];
#
#                    // Loop through each ip range for an ip permissions list
#                    IpRangesLoop:
#                    for (var r in permission.IpRanges) {
#                        var range = permission.IpRanges[r];
#
#                        if (range.CidrIp && range.CidrIp === '0.0.0.0/0') {
#                            var allowedPorts = ports[permission.IpProtocol] || [];
#                            var portRange = permission.ToPort - permission.FromPort;
#                            // Check for all the ports in port range
#                            for (let p=0; p <= portRange; p++) {
#                                var port = permission.FromPort + p;
#
#                                if (!allowedPorts.includes(port)) {
#                                    if (!cidrIps.length) cidrIps.push(range.CidrIp);
#                                    break IpRangesLoop;
#                                }
#                            }
#                        }
#                    }
#
#                        
#                    for (var l in permission.Ipv6Ranges) {
#                        var rangeV6 = permission.Ipv6Ranges[l];
#                            
#                        if (rangeV6.CidrIpv6 && rangeV6.CidrIpv6 === '::/0') {
#                            var allowedV6Ports = ports[permission.IpProtocol] || [];
#                            var portRangeV6 = permission.ToPort - permission.FromPort;
#
#                            // Check for all the ports in port range
#                            for (let p=0; p <= portRangeV6; p++) {
#                                var portV6 = permission.FromPort + p;
#
#                                if (!allowedV6Ports.includes(portV6)) {
#                                    cidrIps.push(rangeV6.CidrIpv6);
#                                    break IpPermissionsLoop;
#                                }
#                            }
#                        }
#                    }
#                }
#
#                if (!cidrIps.length) {
#                    helpers.addResult(results, 0,
#                        `Security group "${group.GroupName}" does not have ports open to 0.0.0.0/0`, 
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Security group "${group.GroupName}" has ports open to ${cidrIps}`,
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }