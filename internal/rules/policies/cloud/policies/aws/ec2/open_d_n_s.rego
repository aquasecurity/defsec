# METADATA
# title :"Open DNS"
# description: "Determine if TCP or UDP port 53 for DNS is open to the public"
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
#   short_code: open-d-n-s 
#   recommended_action: "Restrict TCP and UDP port 53 to known IP addresses"
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
#            'udp': [53],
#            'tcp': [53]
#        };
#
#        var service = 'DNS';
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
#            helpers.findOpenPorts(describeSecurityGroups.data, ports, service, region, results, cache, config, rcb);
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }