# METADATA
# title :"ELB HTTPS Only"
# description: "Ensures ELBs are configured to only accept connections on HTTPS ports."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-options.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ELB
#   severity: LOW
#   short_code: elb-https-only 
#   recommended_action: "Remove non-HTTPS listeners from load balancer."
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
#                    `Unable to query for load balancers: ${helpers.addError(describeLoadBalancers)}`, region);
#                return rcb();
#            }
#
#            if (!describeLoadBalancers.data.length) {
#                helpers.addResult(results, 0, 'No load balancers found', region);
#                return rcb();
#            }
#
#            async.each(describeLoadBalancers.data, function(lb, cb){
#                // arn:aws:elasticloadbalancing:region:account-id:loadbalancer/name
#                var elbArn = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;
#
#                if (!lb.ListenerDescriptions.length) {
#                    helpers.addResult(results, 0,
#                        `ELB "${lb.LoadBalancerName}" is not using any listeners`,
#                        region, elbArn);
#                    return cb();
#                }
#
#                // loop through listeners
#                var non_https_listeners = [];
#                lb.ListenerDescriptions.forEach(function(listener){
#                    // if it is not https add errors to results
#                    if (listener.Listener.Protocol !== 'HTTPS' && listener.Listener.Protocol !== 'SSL'){
#                        non_https_listeners.push(
#                            `${listener.Listener.Protocol}/${listener.Listener.LoadBalancerPort}`
#                        );
#                    }
#                });
#
#                if (non_https_listeners.length) {
#                    helpers.addResult(
#                        results, 2,
#                        `Elb "${lb.LoadBalancerName}" is using these listeners ${non_https_listeners.join(', ')} without HTTPS protocol`,
#                        region, elbArn);
#                } else {
#                    helpers.addResult(results, 0,
#                        `ELB "${lb.LoadBalancerName}" is using listeners with HTTPS protocol only`,
#                        region, elbArn);
#                }
#                cb();
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }