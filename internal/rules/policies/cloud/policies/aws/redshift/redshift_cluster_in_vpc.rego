# METADATA
# title :"Redshift Cluster In VPC"
# description: "Ensures that Amazon Redshift clusters are launched within a Virtual Private Cloud (VPC)."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-clusters.html#cluster-platforms
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Redshift
#   severity: LOW
#   short_code: redshift-cluster-in-vpc 
#   recommended_action: "Update Amazon Redshift cluster and attach it to VPC"
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
#        async.each(regions.redshift, function(region, rcb){
#            var describeClusters = helpers.addSource(cache, source,
#                ['redshift', 'describeClusters', region]);
#
#            if (!describeClusters) return rcb();
#
#            if (describeClusters.err || !describeClusters.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for Redshift clusters: ${helpers.addError(describeClusters)}`, region);
#                return rcb();
#            }
#
#            if (!describeClusters.data.length) {
#                helpers.addResult(results, 0, 'No Redshift clusters found', region);
#                return rcb();
#            }
#
#            describeClusters.data.forEach(cluster => {
#                if (!cluster.ClusterIdentifier) return;
#
#                var clusterIdentifier = cluster.ClusterIdentifier;
#                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:cluster:${clusterIdentifier}`;
#
#                if (cluster.VpcId && cluster.VpcId.length) {
#                    helpers.addResult(results, 0,
#                        'Redshift cluster is launched within a VPC', region, resource);    
#                } else {
#                    helpers.addResult(results, 2,
#                        'Redshift cluster is not launched within a VPC', region, resource);
#                }
#            });
#            
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }