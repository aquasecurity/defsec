# METADATA
# title :"Redshift Cluster Allow Version Upgrade"
# description: "Ensure that version upgrade is enabled for Redshift clusters to automatically receive upgrades during the maintenance window."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.amazonaws.cn/en_us/redshift/latest/mgmt/redshift-mgmt.pdf
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Redshift
#   severity: LOW
#   short_code: redshift-allow-version-upgrade 
#   recommended_action: "Modify Redshift clusters to allow version upgrade"
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
#                    `Unable to query for Redshift clusters: ${helpers.addError(describeClusters)}`, region);
#                return rcb();
#            }
#
#            if (!describeClusters.data.length) {
#                helpers.addResult(results, 0, 'No Redshift clusters found', region);
#                return rcb();
#            }
#
#            async.each(describeClusters.data, function(cluster, ccb){
#                if (!cluster.ClusterIdentifier) return ccb();
#
#                var clusterIdentifier = cluster.ClusterIdentifier;
#                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:cluster:${clusterIdentifier}`;
#
#                if (cluster.AllowVersionUpgrade) {
#                    helpers.addResult(results, 0,
#                        `Redshift cluster "${clusterIdentifier}" is configured to allow version upgrade`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Redshift cluster "${clusterIdentifier}" is not configured to allow version upgrade`,
#                        region, resource);
#                }
#                ccb();
#            });
#            
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }