# METADATA
# title :"NAT Multiple AZ"
# description: "Ensures managed NAT instances exist in at least 2 AZs for availability purposes"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/vpc-nat-gateway.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: nat-multi-az 
#   recommended_action: "Launch managed NAT instances in multiple AZs."
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
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        async.each(regions.vpc, function(region, rcb){
#            var describeVpcs = helpers.addSource(cache, source,
#                ['ec2', 'describeVpcs', region]);
#
#            if (!describeVpcs) return rcb();
#
#            if (describeVpcs.err || !describeVpcs.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for VPCs: ' + helpers.addError(describeVpcs), region);
#                return rcb();
#            }
#
#            if (!describeVpcs.data.length) {
#                helpers.addResult(results, 0, 'No VPCs found', region);
#                return rcb();
#            }
#
#            var vpcMap = {};
#
#            for (var i in describeVpcs.data) {
#                if (!describeVpcs.data[i].VpcId) continue;
#                vpcMap[describeVpcs.data[i].VpcId] = [];
#            }
#
#            var describeNatGateways = helpers.addSource(cache, source,
#                ['ec2', 'describeNatGateways', region]);
#
#            if (! describeNatGateways || describeNatGateways.err || !describeNatGateways.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for NAT gateways: ' + helpers.addError(describeNatGateways), region);
#                return rcb();
#            }
#
#            // Now lookup NATs and map to VPCs
#            for (var n in describeNatGateways.data) {
#                var gw = describeNatGateways.data[n];
#
#                if (gw.VpcId && gw.SubnetId && vpcMap[gw.VpcId] &&
#                    vpcMap[gw.VpcId].indexOf(gw.SubnetId) === -1) {
#                    vpcMap[gw.VpcId].push(gw.SubnetId);
#                }
#            }
#
#            var found = false;
#
#            // Loop through VPCs and add results
#            for (var v in vpcMap) {
#                var numSubnets = vpcMap[v].length;
#
#                if (numSubnets) {
#                    // arn:aws:ec2:region:account-id:vpc/vpc-id
#                    var vpcArn = 'arn:aws:ec2:' + region +
#                                 ':' + accountId + ':vpc/' + v;
#
#                    if (numSubnets === 1) {
#                        helpers.addResult(results, 1,
#                            'VPC is using NAT gateways in only 1 subnet', region, vpcArn);
#                    } else {
#                        helpers.addResult(results, 0,
#                            'VPC is using NAT gateways in ' + numSubnets + ' subnets', region, vpcArn);
#                    }
#
#                    found = true;
#                }
#            }
#
#            if (!found) {
#                helpers.addResult(results, 0,
#                    'No VPCs with NAT gateways found', region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }