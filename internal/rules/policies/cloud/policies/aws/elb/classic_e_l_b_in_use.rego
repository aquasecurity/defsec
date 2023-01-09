# METADATA
# title :"Classic Load Balancers In Use"
# description: "Ensures that HTTP/HTTPS applications are using Application Load Balancer instead of Classic Load Balancer."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://aws.amazon.com/elasticloadbalancing/features/
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ELB
#   severity: LOW
#   short_code: classic-e-l-b-in-use 
#   recommended_action: "Detach Classic Load balancer from HTTP/HTTPS applications and attach Application Load Balancer to those applications"
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
#                var elbArn = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;
#
#                if (!lb.ListenerDescriptions.length) {
#                    helpers.addResult(results, 0,
#                        `ELB "${lb.LoadBalancerName}" is not using any listeners`,
#                        region, elbArn);
#                    return cb();
#                }
#
#                let found;
#
#                if (lb.Instances && lb.Instances.length) {
#                    found = lb.ListenerDescriptions.find(listener => listener.Listener && (listener.Listener.Protocol === 'HTTP' || listener.Listener.Protocol === 'HTTPS'));
#                }
#
#                if (!found) {
#                    helpers.addResult(results, 0,
#                        `Classic load balancer "${lb.LoadBalancerName}" is not in use`,
#                        region, elbArn);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Classic load balancer "${lb.LoadBalancerName}" is in use`,
#                        region, elbArn);
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