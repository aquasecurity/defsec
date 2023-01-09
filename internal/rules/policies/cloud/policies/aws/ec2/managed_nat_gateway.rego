# METADATA
# title :"Managed NAT Gateway In Use"
# description: "Ensure AWS VPC Managed NAT (Network Address Translation) Gateway service is enabled for high availability (HA)."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://aws.amazon.com/blogs/aws/new-managed-nat-network-address-translation-gateway-for-aws/
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: managed-nat-gateway 
#   recommended_action: "Update VPCs to use Managed NAT Gateways instead of NAT instances"
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
#        var foundVpcIds = [];
#
#        async.each(regions.ec2, function(region, rcb){
#            var describeVpcs = helpers.addSource(cache, source,
#                ['ec2', 'describeVpcs', region]);
#            
#            if (!describeVpcs) return rcb();
#
#            if (describeVpcs.err || !describeVpcs.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for VPCs: ${helpers.addError(describeVpcs)}`, region);
#                return rcb();
#            }
#
#            if (!describeVpcs.data.length) {
#                helpers.addResult(results, 0, 'No AWS VPCs found', region);
#                return rcb();
#            }
#
#            var describeNatGateways = helpers.addSource(cache, source,
#                ['ec2', 'describeNatGateways', region]);
#
#            if (!describeNatGateways || describeNatGateways.err || !describeNatGateways.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for NAT Gateways: ${helpers.addError(describeNatGateways)}`, region);
#                return rcb();
#            }
#
#            if (describeNatGateways.data.length) {
#                describeNatGateways.data.forEach(function(nat){
#                    if (nat.VpcId && !foundVpcIds.includes(nat.VpcId)) {
#                        foundVpcIds.push(nat.VpcId);
#                    }
#                });
#            }
#
#            describeVpcs.data.forEach(function(vpc){
#                var resource = `arn:${awsOrGov}:vpc:${region}:${accountId}:/vpc/${vpc.VpcId}`;
#
#                if (foundVpcIds.includes(vpc.VpcId)) {
#                    helpers.addResult(results, 0,
#                        `VPC "${vpc.VpcId}" is using managed NAT Gateway`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `VPC "${vpc.VpcId}" is not using managed NAT Gateway`,
#                        region, resource);
#                }
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }