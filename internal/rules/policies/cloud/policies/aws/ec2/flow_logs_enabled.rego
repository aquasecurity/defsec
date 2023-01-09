# METADATA
# title :"VPC Flow Logs Enabled"
# description: "Ensures VPC flow logs are enabled for traffic logging"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: flow-logs-enabled 
#   recommended_action: "Enable VPC flow logs for each VPC"
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
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        async.each(regions.flowlogs, function(region, rcb){
#            var describeVpcs = helpers.addSource(cache, source,
#                ['ec2', 'describeVpcs', region]);
#
#            if (!describeVpcs) return rcb();
#
#            if (describeVpcs.err || !describeVpcs.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for VPCs: ' + helpers.addError(describeVpcs), region);
#                return rcb();
#            }
#
#            if (!describeVpcs.data.length) {
#                helpers.addResult(results, 0, 'No VPCs found', region);
#                return rcb();
#            }
#
#            var vpcMap = {};
#
#            for (var i in describeVpcs.data) {
#                if (!describeVpcs.data[i].VpcId) continue;
#                vpcMap[describeVpcs.data[i].VpcId] = [];
#            }
#
#            var describeFlowLogs = helpers.addSource(cache, source,
#                ['ec2', 'describeFlowLogs', region]);
#
#            if (! describeFlowLogs || describeFlowLogs.err || !describeFlowLogs.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for flow logs: ' + helpers.addError(describeFlowLogs), region);
#                return rcb();
#            }
#
#            // Now lookup flow logs and map to VPCs
#            for (var f in describeFlowLogs.data) {
#                if (describeFlowLogs.data[f].ResourceId &&
#                    vpcMap[describeFlowLogs.data[f].ResourceId]) {
#                    vpcMap[describeFlowLogs.data[f].ResourceId].push(describeFlowLogs.data[f]);
#                }
#            }
#
#            // Loop through VPCs and add results
#            for (var v in vpcMap) {    
#                var resource = 'arn:' + awsOrGov + ':ec2:' + region + ':' + accountId + ':vpc/' + v;
#                if (!vpcMap[v].length) {
#                    helpers.addResult(results, 2, 'VPC flow logs are not enabled', region, resource);
#                } else {
#                    var activeLogs = false;
#
#                    for (var w in vpcMap[v]) {
#                        if (vpcMap[v][w].FlowLogStatus == 'ACTIVE') {
#                            activeLogs = true;
#                            break;
#                        }
#                    }
#
#                    if (activeLogs) {
#                        helpers.addResult(results, 0, 'VPC flow logs are enabled', region, resource);
#                    } else {
#                        helpers.addResult(results, 2, 'VPC flow logs are enabled, but not active', region, resource);
#                    }
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }