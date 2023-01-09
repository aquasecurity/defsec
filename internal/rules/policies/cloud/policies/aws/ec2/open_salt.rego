# METADATA
# title :"Open Salt"
# description: "Determine if TCP ports 4505 or 4506 for the Salt master are open to the public"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://help.saltstack.com/hc/en-us/articles/360043056331-New-SaltStack-Release-Critical-Vulnerability
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: open-salt 
#   recommended_action: "Restrict TCP ports 4505 and 4506 to known IP addresses"
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
#        var ports = {
#            'tcp': [4505, 4506]
#        };
#
#        var service = 'Salt';
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
#            helpers.findOpenPorts(describeSecurityGroups.data, ports, service, region, results, cache, config, rcb);
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }