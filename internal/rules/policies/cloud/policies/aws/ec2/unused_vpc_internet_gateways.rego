# METADATA
# title :"Unused VPC Internet Gateways"
# description: "Ensures that unused VPC Internet Gateways and Egress-Only Internet Gateways are removed."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: unused-vpc-internet-gateways 
#   recommended_action: "Remove the unused/detached Internet Gateways and Egress-Only Internet Gateways"
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
#            async.parallel([
#                function(lcb){
#                    var describeInternetGateways = helpers.addSource(cache, source,
#                        ['ec2', 'describeInternetGateways', region]);
#
#                    if (!describeInternetGateways) return lcb();
#                    
#                    if (describeInternetGateways.err || !describeInternetGateways.data) {
#                        helpers.addResult(results, 3,
#                            `Unable to query for Internet Gateways: ${helpers.addError(describeInternetGateways)}`, region);
#                        return lcb();
#                    }
#
#                    if (!describeInternetGateways.data.length) {
#                        helpers.addResult(results, 0, 'No Internet Gateways found', region);
#                    }
#                    
#                    let resource = `arn:${awsOrGov}:vpc:${region}:${accountId}:internet-gateway`;
#                    loopGWForResults(describeInternetGateways, results, region, resource);
#
#                    lcb();
#                },
#                function(lcb){
#                    var describeEgressOnlyInternetGateways = helpers.addSource(cache, source,
#                        ['ec2', 'describeEgressOnlyInternetGateways', region]);
#                    
#                    if (!describeEgressOnlyInternetGateways) return lcb();
#                
#                    if (describeEgressOnlyInternetGateways.err || !describeEgressOnlyInternetGateways.data) {
#                        helpers.addResult(results, 3,
#                            `Unable to query for Egress-Only Internet Gateways: ${helpers.addError(describeEgressOnlyInternetGateways)}`,
#                            region);
#                        return lcb();
#                    }
#
#                    if (!describeEgressOnlyInternetGateways.data.length) {
#                        helpers.addResult(results, 0, 'No Egress-Only Internet Gateways found', region);
#                    }
#
#                    let resource = `arn:${awsOrGov}:vpc:${region}:${accountId}:egress-only-internet-gateway`;
#                    loopGWForResults(describeEgressOnlyInternetGateways, results, region, resource, 'Egress-Only');
#
#                    lcb();
#                }
#            ], function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }