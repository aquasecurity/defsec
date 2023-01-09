# METADATA
# title :"PrivateLink in Use for Transfer for SFTP Server Endpoints"
# description: "Ensure that AWS Transfer for SFTP server endpoints are configured to use VPC endpoints powered by AWS PrivateLink."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/transfer/latest/userguide/update-endpoint-type-vpc.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Transfer
#   severity: LOW
#   short_code: transfer-private-link-in-use 
#   recommended_action: "Configure the SFTP server endpoints to use endpoints powered by PrivateLink."
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
#            listServers.data.forEach(server => {
#                const isPrivate = (server.EndpointType && server.EndpointType != 'PUBLIC') ? true : false;
#                helpers.addResult(results, isPrivate ? 0 : 2,
#                    `Server '${server.ServerId}' is ${isPrivate ? '': 'not '}configured with private endpoint`, region, server.Arn);
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }