# METADATA
# title :"Virtual Private Gateway In VPC"
# description: "Ensure Virtual Private Gateways are associated with at least one VPC."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/vpn/latest/s2svpn/SetUpVPNConnections.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: vpn-gateway-in-vpc 
#   recommended_action: "Check if virtual private gateways have vpc associated"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        async.each(regions.ec2, function(region, rcb){
#            var describeVpnGateways = helpers.addSource(cache, source,
#                ['ec2', 'describeVpnGateways', region]);
#
#            if (!describeVpnGateways) return rcb();
#
#            if (describeVpnGateways.err || !describeVpnGateways.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for Virtual Private Gateways: ${helpers.addError(describeVpnGateways)}`,
#                    region);
#                return rcb();
#            }
#
#            if (!describeVpnGateways.data.length) {
#                helpers.addResult(results, 0,
#                    'No Virtual Private Gateways found', region);
#                return rcb();
#            }
#
#            describeVpnGateways.data.forEach(function(vpn){
#                var resource = `arn:${awsOrGov}:vpc:${region}:${accountId}:vpn-gateway/${vpn.VpnGatewayId}`;
#                if (vpn.VpcAttachments && vpn.VpcAttachments.length) {
#                    let attached = vpn.VpcAttachments.find(attachment => attachment.VpcId && attachment.State && attachment.State.toUpperCase() == 'ATTACHED');
#                    
#                    if (attached) {
#                        helpers.addResult(results, 0,
#                            'Virtual Private Gateway is associated with VPC',
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            'Virtual Private Gateway is not associated with VPC',
#                            region, resource);
#                    }
#                } else {
#                    helpers.addResult(results, 2,
#                        'Virtual Private Gateway is not associated with VPC',
#                        region, resource);
#                }
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }