# METADATA
# title :"RDS Publicly Accessible"
# description: "Ensures RDS instances are not launched into the public cloud"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:RDS
#   severity: LOW
#   short_code: rds-publicly-accessible 
#   recommended_action: "Remove the public endpoint from the RDS instance"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.rds, function(region, rcb){
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
#            for (var i in describeDBInstances.data) {
#                // For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
#                var db = describeDBInstances.data[i];
#                var dbResource = db.DBInstanceArn;
#
#                if (db.PubliclyAccessible) {
#                    helpers.addResult(results, 2, 'RDS instance is publicly accessible', region, dbResource);
#                } else {
#                    helpers.addResult(results, 0, 'RDS instance is not publicly accessible', region, dbResource);
#                }
#            }
#            
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }