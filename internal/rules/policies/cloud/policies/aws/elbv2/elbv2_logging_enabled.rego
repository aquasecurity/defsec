# METADATA
# title :"ELBv2 Logging Enabled"
# description: "Ensures load balancers have request logging enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ELBv2
#   severity: LOW
#   short_code: elbv2-logging-enabled 
#   recommended_action: "Enable ELB request logging"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.elb, function(region, rcb){
#            var describeLoadBalancers = helpers.addSource(cache, source,
#                ['elbv2', 'describeLoadBalancers', region]);
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
#                helpers.addResult(results, 0, 'No load balancers present', region);
#                return rcb();
#            }
#
#            async.each(describeLoadBalancers.data, function(lb, cb){
#                // loop through listeners
#                var describeLoadBalancerAttributes = helpers.addSource(cache, source,
#                    ['elbv2', 'describeLoadBalancerAttributes', region, lb.DNSName]);
#
#                if (describeLoadBalancerAttributes &&
#                    describeLoadBalancerAttributes.data &&
#                    describeLoadBalancerAttributes.data.Attributes &&
#                    describeLoadBalancerAttributes.data.Attributes.length) {
#                    for (let attribute of describeLoadBalancerAttributes.data.Attributes) {
#                        if (attribute.Key && attribute.Key === 'access_logs.s3.enabled') {
#                            if (attribute.Value === 'false') {
#                                helpers.addResult(results, 2,
#                                    'Logging not enabled for ' + lb.DNSName, region, lb.LoadBalancerArn);
#                            } else {
#                                helpers.addResult(results, 0,
#                                    'Logging enabled for ' + lb.DNSName, region, lb.LoadBalancerArn);
#                            }
#                            break;
#                        }
#                    }
#                } else {
#                    helpers.addResult(results, 2,
#                        'no load balancer attributes found for: ' + lb.DNSName, region, lb.LoadBalancerArn);
#                }
#                cb();
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }