# METADATA
# title :"Redshift Publicly Accessible"
# description: "Ensures Redshift clusters are not launched into the public cloud"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/redshift/latest/mgmt/getting-started-cluster-in-vpc.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Redshift
#   severity: LOW
#   short_code: redshift-publicly-accessible 
#   recommended_action: "Remove the public endpoint from the Redshift cluster"
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
#        var accountId = helpers.addSource(cache, source,
#            ['sts', 'getCallerIdentity', acctRegion, 'data']);
#        var awsOrGov = helpers.defaultPartition(settings);
#
#        async.each(regions.redshift, function(region, rcb){
#            var describeClusters = helpers.addSource(cache, source,
#                ['redshift', 'describeClusters', region]);
#
#            if (!describeClusters) return rcb();
#
#            if (describeClusters.err || !describeClusters.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for Redshift clusters: ' + helpers.addError(describeClusters), region);
#                return rcb();
#            }
#
#            if (!describeClusters.data.length) {
#                helpers.addResult(results, 0, 'No Redshift clusters found', region);
#                return rcb();
#            }
#
#            for (var i in describeClusters.data) {
#                // For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
#                var cluster = describeClusters.data[i];
#                var clusterIdentifier = cluster.ClusterIdentifier;
#                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:cluster:${clusterIdentifier}`;
#
#                if (cluster.PubliclyAccessible) {
#                    helpers.addResult(results, 1, 'Redshift cluster is publicly accessible', region, resource);
#                } else {
#                    helpers.addResult(results, 0, 'Redshift cluster is not publicly accessible', region, resource);
#                }
#            }
#            
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }