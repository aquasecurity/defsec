# METADATA
# title :"RDS Instance Has Tags"
# description: "Ensure that AWS RDS instance have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:RDS
#   severity: LOW
#   short_code: rds-instance-has-tags 
#   recommended_action: "Modify the RDS instance to add tags."
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
#            for ( var rdsInstance of describeDBInstances.data){
#                if (!rdsInstance.TagList || !rdsInstance.TagList.length){
#                    helpers.addResult(results, 2, 'RDS instance does not have any tags',
#                        region, rdsInstance.DBInstanceArn);
#                } else {
#                    helpers.addResult(results, 0, 'RDS instance has tags', region, rdsInstance.DBInstanceArn);
#                }
#            }
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }