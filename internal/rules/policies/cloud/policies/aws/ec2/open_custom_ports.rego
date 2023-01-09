# METADATA
# title :"Open Custom Ports"
# description: "Ensure that defined custom ports are not open to public."
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
#   short_code: open-custom-ports 
#   recommended_action: "Modify the security group to ensure the defined custom ports are not exposed publicly"
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
#        var restricted_open_ports = settings.restricted_open_ports || this.settings.restricted_open_ports.default;
#
#        if (!restricted_open_ports.length) return callback();
#
#        restricted_open_ports = restricted_open_ports.split(',');
#
#        var ports = {};
#        restricted_open_ports.forEach(port => {
#            var [protocol, portNo] = port.split(':');
#            if (ports[protocol]) {
#                ports[protocol].push(portNo);
#            } else {
#                ports[protocol] = [portNo];
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
#                helpers.addResult(results, 0, 'No security groups present', region);
#                return rcb();
#            }
#
#            helpers.findOpenPorts(describeSecurityGroups.data, ports, 'custom', region, results, cache, config, rcb);
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }