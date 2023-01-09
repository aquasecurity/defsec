# METADATA
# title :"EMR Cluster In VPC"
# description: "Ensure that your Amazon Elastic MapReduce (EMR) clusters are provisioned using the AWS VPC platform instead of EC2-Classic platform."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-vpc-launching-job-flows.htmll
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EMR
#   severity: LOW
#   short_code: emr-cluster-in-v-p-c 
#   recommended_action: "EMR clusters Available in VPC"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.emr, function(region, rcb){
#            var listClusters = helpers.addSource(cache, source,
#                ['emr', 'listClusters', region]);
#
#            if (!listClusters) return rcb();
#
#            if (listClusters.err || !listClusters.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for EMR clusters: ' + helpers.addError(listClusters), region);
#                return rcb();
#            }
#
#            if (!listClusters.data.length) {
#                helpers.addResult(results, 0, 'No EMR cluster found', region);
#                return rcb();
#            }
#
#            var describeAccountAttributes = helpers.addSource(cache, source,
#                ['ec2', 'describeAccountAttributes', region]);
#
#            if (!describeAccountAttributes || describeAccountAttributes.err || !describeAccountAttributes.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for supported platforms: ' + helpers.addError(describeAccountAttributes), region);
#                return rcb();
#            }
#
#            if (describeAccountAttributes.data.length) {
#                var supportedPlatforms = describeAccountAttributes.data.find(attribute => attribute.AttributeName == 'supported-platforms');
#
#                if (supportedPlatforms && supportedPlatforms.AttributeValues) {
#                    let ec2ClassicFound = supportedPlatforms.AttributeValues.find(value => value.AttributeValue && value.AttributeValue.toUpperCase() === 'EC2');
#                    if (!ec2ClassicFound) {
#                        helpers.addResult(results, 0, 'EC2 account attribute allows only VPC supported platform', region);
#                        return rcb();
#                    }
#                }
#            }
#        
#            for (let cluster of listClusters.data) {
#                if (!cluster.Id) continue;
#
#                var resource = cluster.ClusterArn;
#            
#                var describeCluster = helpers.addSource(cache, source,
#                    ['emr', 'describeCluster', region, cluster.Id]);
#            
#                if (!describeCluster || describeCluster.err || !describeCluster.data || !describeCluster.data.Cluster) {
#                    helpers.addResult(results, 3,
#                        'Unable to query for EMR cluster', region, resource);
#                    continue;
#                }
#
#                if (describeCluster.data.Cluster.Ec2InstanceAttributes &&
#                    describeCluster.data.Cluster.Ec2InstanceAttributes.Ec2SubnetId &&
#                    describeCluster.data.Cluster.Ec2InstanceAttributes.Ec2SubnetId.length) {
#                    helpers.addResult(results, 0,
#                        `EMR cluster  "${cluster.Name}" is in VPC`, region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `EMR cluster  "${cluster.Name}" is not in VPC`, region, resource);
#                }
#            }
#
#            rcb();
#        }, function() {
#            return callback(null, results, source);
#        });
#    }