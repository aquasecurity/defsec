# METADATA
# title :"RDS Logging Enabled"
# description: "Ensures logging is configured for RDS instances"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:RDS
#   severity: LOW
#   short_code: rds-logging-enabled 
#   recommended_action: "Modify the RDS instance to enable logging as required."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var describeDBEngineVersions = helpers.addSource(cache, source,
#            ['rds', 'describeDBEngineVersions', regions.default[0]]);
#
#        async.each(regions.rds, function(region, rcb) {
#            var describeDBInstances = helpers.addSource(cache, source,
#                ['rds', 'describeDBInstances', region]);
#            if (!describeDBInstances) return rcb();
#            if (describeDBInstances.err || !describeDBInstances.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for RDS instances: ' + helpers.addError(describeDBInstances), region);
#                return rcb();
#            }
#            if (!describeDBInstances.data.length) {
#                helpers.addResult(results, 0, 'No RDS instances found', region);
#                return rcb();
#            }
#
#            if (!describeDBEngineVersions) return rcb();
#
#            if (describeDBEngineVersions.err || !describeDBEngineVersions.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for RDS engine versions: ' + helpers.addError(describeDBEngineVersions), region);
#                return rcb();
#            }
#            
#            var eligibleDBEngineVersions = describeDBEngineVersions.data.filter(function(dbEngine) {
#                return dbEngine.SupportsLogExportsToCloudwatchLogs;
#            });
#
#            for (var i in describeDBInstances.data) {
#                // For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
#                var db = describeDBInstances.data[i];
#                var dbResource = db.DBInstanceArn;
#
#                if (db.EnabledCloudwatchLogsExports && db.EnabledCloudwatchLogsExports.length) {
#                    helpers.addResult(results, 0, 'Logging is enabled', region, dbResource);
#                } else {
#                    // If logging is not enabled, see if it *can* be enabled.
#                    var matchingDBEngineVersions = eligibleDBEngineVersions.filter(function(dbEngine) {
#                        return dbEngine.Engine === db.Engine && dbEngine.EngineVersion === db.EngineVersion;
#                    });
#                    if (matchingDBEngineVersions.length) {
#                        helpers.addResult(results, 2, 'Logging is not enabled', region, dbResource);
#                    } else {
#                        helpers.addResult(results, 0, 'Logging is not enabled, but cannot be enabled', region, dbResource);
#                    }
#                }
#            }
#            
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }