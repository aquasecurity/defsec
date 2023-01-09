# METADATA
# title :"ELB Cross-Zone Load Balancing"
# description: "Ensures that AWS ELBs have cross-zone load balancing enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-disable-crosszone-lb.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ELB
#   severity: LOW
#   short_code: crosszone-load-balancing 
#   recommended_action: "Update AWS ELB to enable cross zone load balancing"
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
#                var resource = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;
#
#                var describeLoadBalancerAttributes = helpers.addSource(cache, source,
#                    ['elb', 'describeLoadBalancerAttributes', region, lb.DNSName]);
#
#                if (!describeLoadBalancerAttributes ||
#                    !describeLoadBalancerAttributes.data ||
#                    describeLoadBalancerAttributes.err || 
#                    !describeLoadBalancerAttributes.data || 
#                    !describeLoadBalancerAttributes.data.LoadBalancerAttributes) {
#                    helpers.addResult(results, 3,
#                        `Unable to query load balancer attributes: ${helpers.addError(describeLoadBalancerAttributes)}`,
#                        region, resource);
#                    return cb();
#                }
#
#                if (describeLoadBalancerAttributes.data.LoadBalancerAttributes.CrossZoneLoadBalancing &&
#                    describeLoadBalancerAttributes.data.LoadBalancerAttributes.CrossZoneLoadBalancing.Enabled) {
#                    helpers.addResult(results, 0,
#                        `AWS ELB "${lb.LoadBalancerName}" has cross-zone load balancing enabled`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `AWS ELB "${lb.LoadBalancerName}" does not have cross-zone load balancing enabled`,
#                        region, resource);
#                }
#
#                cb();
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }