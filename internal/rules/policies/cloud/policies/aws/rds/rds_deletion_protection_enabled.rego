# METADATA
# title :"RDS Deletion Protection Enabled"
# description: "Ensures deletion protection is enabled for RDS database instances."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:RDS
#   severity: LOW
#   short_code: rds-deletion-protection-enabled 
#   recommended_action: "Modify the RDS instances to enable deletion protection."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.rds, function(region, rcb) {
#            var describeDBInstances = helpers.addSource(cache, source,
#                ['rds', 'describeDBInstances', region]);
#
#            if (!describeDBInstances) return rcb();
#
#            if (describeDBInstances.err || !describeDBInstances.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for RDS instances: ' + helpers.addError(describeDBInstances), region);
#                return rcb();
#            }
#
#            if (!describeDBInstances.data.length) {
#                helpers.addResult(results, 0, 'No RDS instances found', region);
#                return rcb();
#            }
#
#            describeDBInstances.data.forEach(instance => {
#                if (!instance.DBInstanceArn) return;
#
#                if (instance.DeletionProtection) {
#                    helpers.addResult(results, 0,
#                        'RDS instance has deletion protection enabled', region, instance.DBInstanceArn);
#                } else {
#                    helpers.addResult(results, 2,
#                        'RDS instance does not have deletion protection enabled', region, instance.DBInstanceArn);
#                }
#            });
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }