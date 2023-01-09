# METADATA
# title :"Domain Expiry"
# description: "Ensures domains are not expiring too soon"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/registrar.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Route53
#   severity: LOW
#   short_code: domain-expiry 
#   recommended_action: "Reregister the expiring domain"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#
#        var region = helpers.defaultRegion(settings);
#
#        var listDomains = helpers.addSource(cache, source,
#            ['route53domains', 'listDomains', region]);
#
#        if (!listDomains) return callback(null, results, source);
#
#        if (listDomains.err || !listDomains.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for domains: ' + helpers.addError(listDomains));
#            return callback(null, results, source);
#        }
#
#        if (!listDomains.data.length) {
#            helpers.addResult(results, 0, 'No domains registered through Route53');
#            return callback(null, results, source);
#        }
#
#        for (var domain of listDomains.data) {
#            if (domain.Expiry) {
#                var difference = Math.round((new Date(domain.Expiry).getTime() - new Date().getTime())/(24*60*60*1000));
#                var returnMsg = 'Domain: ' + domain.DomainName + ' expires in ' + difference + ' days';
#
#                if (difference > 35) {
#                    helpers.addResult(results, 0, returnMsg, 'global', domain.DomainName);
#                } else if (domain.DomainName.endsWith(('.com.ar, .com.br, .jp')) && difference > 30) {
#                    helpers.addResult(results, 0, returnMsg, 'global', domain.DomainName);
#                } else if (difference > 0) {
#                    helpers.addResult(results, 2, returnMsg, 'global', domain.DomainName);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Domain: ' + domain.DomainName + ' expired ' + difference + ' days ago',
#                        'global', domain.DomainName);
#                }
#            } else {
#                helpers.addResult(results, 3,
#                    'Expiration for domain: ' + domain.DomainName + ' could not be determined',
#                    'global', domain.DomainName);
#            }
#        }
#
#        callback(null, results, source);
#    }