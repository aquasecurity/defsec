# METADATA
# title :"Unused Elastic Network Interfaces"
# description: "Ensures that unused AWS Elastic Network Interfaces (ENIs) are removed."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: unused-eni 
#   recommended_action: "Delete the unused AWS Elastic Network Interfaces"
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
#        async.each(regions.ec2, function(region, rcb) {
#            var describeNetworkInterfaces = helpers.addSource(cache, source,
#                ['ec2', 'describeNetworkInterfaces', region]);
#
#            if (!describeNetworkInterfaces) return rcb();
#
#            if (describeNetworkInterfaces.err || !describeNetworkInterfaces.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query AWS ENIs: ${helpers.addError(describeNetworkInterfaces)}`, region);
#                return rcb();
#            }
#
#            if (!describeNetworkInterfaces.data.length) {
#                helpers.addResult(results, 0, 'No AWS ENIs found', region);
#                return rcb();
#            }
#
#            describeNetworkInterfaces.data.forEach(function(eni){
#                var resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:network-interface/${eni.NetworkInterfaceId}`;
#
#                if (eni.Status && eni.Status === 'in-use') {
#                    helpers.addResult(results, 0,
#                        `AWS ENI "${eni.NetworkInterfaceId}" is in use`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `AWS ENI "${eni.NetworkInterfaceId}" is not in use`,
#                        region, resource);
#                }
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }