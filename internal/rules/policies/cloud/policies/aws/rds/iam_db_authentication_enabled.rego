# METADATA
# title :"RDS IAM Database Authentication Enabled"
# description: "Ensures IAM Database Authentication is enabled for RDS database instances to manage database access"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:RDS
#   severity: LOW
#   short_code: iam-db-authentication-enabled 
#   recommended_action: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication."
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
#                    `Unable to query for RDS instances: ${helpers.addError(describeDBInstances)}`, region);
#                return rcb();
#            }
#
#            if (!describeDBInstances.data.length) {
#                helpers.addResult(results, 0, 'No RDS instances found', region);
#                return rcb();
#            }
#
#            describeDBInstances.data.forEach(instance => {
#                if (!instance.DBInstanceArn || !instance.Engine) return;
#
#                if (['postgres', 'mysql'].includes(instance.Engine)) {
#                    if (instance.IAMDatabaseAuthenticationEnabled) {
#                        helpers.addResult(results, 0,
#                            'RDS instance has IAM Database Authentication enabled', region, instance.DBInstanceArn);
#                    } else {
#                        helpers.addResult(results, 2,
#                            'RDS instance does not have IAM Database Authentication enabled', region, instance.DBInstanceArn);
#                    }
#                } else {
#                    helpers.addResult(results, 0,
#                        `RDS instance engine type ${instance.Engine} does not support IAM database authentication`, region, instance.DBInstanceArn);
#                }
#            });
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }