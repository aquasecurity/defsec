# METADATA
# title :"Default VPC Exists"
# description: "Determines whether the default VPC exists."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/default-vpc.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: default-vpc-exists 
#   recommended_action: "Move resources from the default VPC to a new VPC created for that application or resource group."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        var regions = helpers.regions(settings);
#
#        async.each(regions.vpc, function(region, rcb){
#            var describeVpcs = helpers.addSource(cache, source, ['ec2', 'describeVpcs', region]);
#
#            if (!describeVpcs) return rcb();
#
#            if (describeVpcs.err || !describeVpcs.data) {
#                helpers.addResult(results, 3, `Unable to query for VPCs: ${helpers.addError(describeVpcs)}`, region);
#                return rcb();
#            }
#
#            if (!describeVpcs.data.length) {
#                helpers.addResult(results, 0, 'No VPCs present', region);
#                return rcb();
#            }
#
#            for (var v in describeVpcs.data) {
#                var vpc = describeVpcs.data[v];
#                // arn:${Partition}:ec2:${Region}:${Account}:vpc/${VpcId}
#                var arn = 'arn:' + awsOrGov + ':ec2:' + region + ':' + accountId + ':vpc/' + vpc.VpcId;
#                if (vpc.IsDefault) {
#                    helpers.addResult(results, 2, 'Default VPC present', region, arn);
#                    return rcb();
#                }
#            }
#
#            helpers.addResult(results, 0, 'Default VPC not present', region);
#            return rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }