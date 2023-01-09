# METADATA
# title :"Insecure Ciphers"
# description: "Detect use of insecure ciphers on ELBs"
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
#   short_code: insecure-ciphers 
#   recommended_action: "Update your ELBs to use the recommended cipher suites"
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
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#        var awsOrGov = helpers.defaultPartition(settings);
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
#                helpers.addResult(results, 0, 'No load balancers present', region);
#                return rcb();
#            }
#
#            async.each(describeLoadBalancers.data, function(lb, cb){
#                if (!lb.DNSName) return cb();
#                var resource = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;
#
#                var describeLoadBalancerPolicies = helpers.addSource(cache, source,
#                    ['elb', 'describeLoadBalancerPolicies', region, lb.DNSName]);
#
#                // If the LB wasn't using HTTPS, just skip it
#                if (!describeLoadBalancerPolicies ||
#                    (!describeLoadBalancerPolicies.err && !describeLoadBalancerPolicies.data)) return cb();
#
#                if (describeLoadBalancerPolicies.err || !describeLoadBalancerPolicies.data) {
#                    helpers.addResult(results, 3,
#                        'Unable to query load balancer policies for ELB: ' + lb.LoadBalancerName +
#                        ': ' + helpers.addError(describeLoadBalancerPolicies),
#                        region, resource);
#
#                    return cb();
#                }
#
#                for (var i in describeLoadBalancerPolicies.data.PolicyDescriptions) {
#                    var policyDesc = describeLoadBalancerPolicies.data.PolicyDescriptions[i];
#
#                    var elbBad = [];
#
#                    for (var j in policyDesc.PolicyAttributeDescriptions) {
#                        var policyAttrDesc = policyDesc.PolicyAttributeDescriptions[j];
#
#                        if (policyAttrDesc.AttributeValue === 'true' &&
#                            badCiphers.indexOf(policyAttrDesc.AttributeName) > -1) {
#                            elbBad.push(policyAttrDesc.AttributeName);
#                        }
#                    }
#
#                    if (elbBad.length) {
#                        helpers.addResult(results, 1,
#                            'ELB: ' + lb.LoadBalancerName + ' uses insecure protocols or ciphers: ' + elbBad.join(', '),
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 0,
#                            'ELB: ' + lb.LoadBalancerName + ' uses secure protocols and ciphers',
#                            region, resource);
#                    }
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