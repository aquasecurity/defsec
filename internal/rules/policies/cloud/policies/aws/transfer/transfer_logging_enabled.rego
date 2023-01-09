# METADATA
# title :"Transfer Logging Enabled"
# description: "Ensures AWS Transfer servers have CloudWatch logging enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/transfer/latest/userguide/monitoring.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Transfer
#   severity: LOW
#   short_code: transfer-logging-enabled 
#   recommended_action: "Provide a valid IAM service role for AWS Transfer servers."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.transfer, function(region, rcb){
#            var listServers = helpers.addSource(cache, source,
#                ['transfer', 'listServers', region]);
#
#            if (!listServers) return rcb();
#
#            if (listServers.err || !listServers.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for Transfer servers: ' + helpers.addError(listServers), region);
#                return rcb();
#            }
#
#            if (!listServers.data.length) {
#                helpers.addResult(results, 0, 'No Transfer servers found', region);
#                return rcb();
#            }
#
#            for (var i in listServers.data) {
#                var server = listServers.data[i];
#                var arn = server.Arn;
#
#                if (server.LoggingRole && server.LoggingRole.length) {
#                    helpers.addResult(results, 0, 'Logging role is properly configured for Transfer server', region, arn);
#                } else {
#                    helpers.addResult(results, 2, 'Logging role is not configured for Transfer server', region, arn);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }