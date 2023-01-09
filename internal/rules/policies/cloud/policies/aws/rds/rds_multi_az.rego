# METADATA
# title :"RDS Multiple AZ"
# description: "Ensures that RDS instances are created to be cross-AZ for high availability."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:RDS
#   severity: LOW
#   short_code: rds-multi-az 
#   recommended_action: "Modify the RDS instance to enable scaling across multiple availability zones."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            rds_multi_az_ignore_replicas: settings.rds_multi_az_ignore_replicas || this.settings.rds_multi_az_ignore_replicas.default
#        };
#
#        config.rds_multi_az_ignore_replicas = (config.rds_multi_az_ignore_replicas == 'true');
#
#        var custom = helpers.isCustom(settings, this.settings);
#
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
#            // loop through Rds Instances
#            describeDBInstances.data.forEach(function(Rds){
#                if (Rds.Engine === 'aurora' ||
#                    Rds.Engine === 'aurora-postgresql' ||
#                    Rds.Engine === 'aurora-mysql') {
#                    helpers.addResult(results, 0,
#                        'RDS Aurora instances are multi-AZ',
#                        region, Rds.DBInstanceArn);
#                } else if (Rds.Engine === 'docdb') {
#                    helpers.addResult(results, 0,
#                        'RDS DocDB instances multi-AZ property is not supported in this context',
#                        region, Rds.DBInstanceArn);
#                } else if (Rds.MultiAZ){
#                    helpers.addResult(results, 0,
#                        'RDS instance has multi-AZ enabled',
#                        region, Rds.DBInstanceArn);
#                } else {
#                    if (config.rds_multi_az_ignore_replicas &&
#                        Rds.ReadReplicaSourceDBInstanceIdentifier) {
#                        helpers.addResult(results, 0,
#                            'RDS instance does not have multi-AZ enabled but is a read replica',
#                            region, Rds.DBInstanceArn, custom);
#                    } else {
#                        helpers.addResult(results, 2,
#                            'RDS instance does not have multi-AZ enabled',
#                            region, Rds.DBInstanceArn, custom);
#                    }
#                }
#            });
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }