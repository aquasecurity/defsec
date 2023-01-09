# METADATA
# title :"ELB Has Tags"
# description: "Ensure that ELBs have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_AddTags.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ELB
#   severity: LOW
#   short_code: elb-has-tags 
#   recommended_action: "Modify ELB and add tags."
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
#        async.each(regions.elb, function(region, rcb){
#            var describeLoadBalancers = helpers.addSource(cache, source,
#                ['elb', 'describeLoadBalancers', region]);
#                
#            if (!describeLoadBalancers) return rcb();
#
#            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for load balancers: ' + helpers.addError(describeLoadBalancers), region);
#                return rcb();
#            }
#
#            if (!describeLoadBalancers.data.length) {
#                helpers.addResult(results, 0, 'No load balancers found', region);
#                return rcb();
#            }
#            const arnList = [];
#            for (let lb of describeLoadBalancers.data){
#                if (!lb.LoadBalancerName) continue;
#
#                var elbArn = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;
#                arnList.push(elbArn);
#            }
#            helpers.checkTags(cache, 'ElasticLoadbalancing', arnList, region, results);
#            return rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }