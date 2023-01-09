# METADATA
# title :"VPN Tunnel State"
# description: "Ensures that each AWS Virtual Private Network (VPN) connection has all tunnels up."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/vpn/latest/s2svpn/VPNTunnels.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: vpn-tunnel-state 
#   recommended_action: "Establish a successful VPN connection using IKE or IPsec configuration"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var enable_vpn_tunnel_state = (settings.enable_vpn_tunnel_state || this.settings.enable_vpn_tunnel_state.default);
#
#        if (!enable_vpn_tunnel_state || enable_vpn_tunnel_state == 'false') return callback(null, results, source);
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        async.each(regions.ec2, function(region, rcb){
#            var describeVpnConnections = helpers.addSource(cache, source,
#                ['ec2', 'describeVpnConnections', region]);
#
#            if (!describeVpnConnections) return rcb();
#
#            if (describeVpnConnections.err || !describeVpnConnections.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for VPN connections: ${helpers.addError(describeVpnConnections)}`,
#                    region);
#                return rcb();
#            }
#
#            if (!describeVpnConnections.data.length) {
#                helpers.addResult(results, 0,
#                    'No VPN connections found', region);
#                return rcb();
#            }
#
#            for (var vpn of describeVpnConnections.data) {
#                if (!vpn.VpnConnectionId) continue;
#
#                var resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:vpn-connection/${vpn.VpnConnectionId}`;
#                var tunnelDown = false;
#
#                if (vpn.VgwTelemetry && vpn.VgwTelemetry.length) {
#                    for (var vgw of vpn.VgwTelemetry) {
#                        if (vgw.Status && vgw.Status.toUpperCase() === 'DOWN') {
#                            tunnelDown = true;
#                            break;
#                        }
#                    }
#                } else {
#                    helpers.addResult(results, 2,
#                        `VPN connection "${vpn.VpnConnectionId}" does not have any tunnel configured`,
#                        region, resource);
#                    continue;
#                }
#
#                if (!tunnelDown) {
#                    helpers.addResult(results, 0,
#                        `VPN connection "${vpn.VpnConnectionId}" has all tunnels UP`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `VPN connection "${vpn.VpnConnectionId}" has tunnel down`,
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }