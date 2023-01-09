# METADATA
# title :"ELBv2 HTTPS Only"
# description: "Ensures ELBs are configured to only accept connections on HTTPS ports."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-options.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ELBv2
#   severity: LOW
#   short_code: elbv2-https-only 
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
#                var describeListeners = helpers.addSource(cache, source,
#                    ['elbv2', 'describeListeners', region, lb.DNSName]);
#
#                // loop through listeners
#                var non_https_listener = [];
#                var noListeners = true;
#                var elbArn = lb.LoadBalancerArn;
#                if (describeListeners && describeListeners.data && describeListeners.data.Listeners && describeListeners.data.Listeners.length) {
#                    noListeners = false;
#                    describeListeners.data.Listeners.forEach(function(listener){
#                        // if it is not https add errors to results
#                        if (listener.Protocol && listener.Port && (listener.Protocol !== 'HTTPS' && listener.Protocol !== 'SSL')) {
#                            non_https_listener.push(
#                                listener.Protocol + ' / ' +
#                                listener.Port
#                            );
#                        }
#
#                    });
#                }
#                if (non_https_listener && non_https_listener.length){
#                    var msg = 'The following listeners are not using HTTPS-only: ';
#                    helpers.addResult(results, 2,
#                        msg + non_https_listener.join(', '), region, elbArn);
#                } else if (non_https_listener && !non_https_listener.length) {
#                    helpers.addResult(results, 0, 'All listeners are HTTPS-only', region, elbArn);
#                } else if (noListeners) {
#                    helpers.addResult(results, 0, 'No listeners found', region, elbArn);
#                }
#                cb();
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }