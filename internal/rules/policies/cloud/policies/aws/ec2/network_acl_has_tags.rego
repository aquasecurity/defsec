# METADATA
# title :"Network ACL has Tags"
# description: "Ensure that Amazon Network ACLs have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: network-acl-has-tags 
#   recommended_action: "Modify Network ACL and add tags."
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
#            var describeNetworkAcls = helpers.addSource(cache, source,
#                ['ec2', 'describeNetworkAcls', region]);
#
#            if (!describeNetworkAcls) return rcb();
#
#            if (describeNetworkAcls.err || !describeNetworkAcls.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for Network ACLs: ${helpers.addError(describeNetworkAcls)}`, region);
#                return rcb();
#            }
#
#            if (!describeNetworkAcls.data.length) {
#                helpers.addResult(results, 0, 'No Network ACLs found', region);
#                return rcb();
#            }
#            for (let nAcl of describeNetworkAcls.data) {
#                if (!nAcl.NetworkAclId) continue;
#
#                var resourceARN = `arn:${awsOrGov}:ec2:${region}:${accountId}:network-acl/${nAcl.NetworkAclId}`;
#
#                if (!nAcl.Tags || !nAcl.Tags.length) {
#                    helpers.addResult(results, 2, 'Network ACL does not have tags', region, resourceARN);
#                } else {
#                    helpers.addResult(results, 0, 'Network ACL has tags', region, resourceARN);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }