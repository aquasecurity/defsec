# METADATA
# title :"Domain Auto Renew"
# description: "Ensures domains are set to auto renew through Route53"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/Route53/latest/APIReference/api-enable-domain-auto-renew.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Route53
#   severity: LOW
#   short_code: domain-auto-renew 
#   recommended_action: "Enable auto renew for the domain"
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
#        for (var i in listDomains.data) {
#            var domain = listDomains.data[i];
#
#            if (domain.AutoRenew) {
#                helpers.addResult(results, 0,
#                    'Domain: ' + domain.DomainName + ' has auto renew enabled',
#                    'global', domain.DomainName);
#            } else {
#                helpers.addResult(results, 1,
#                    'Domain: ' + domain.DomainName + ' does not have auto renew enabled',
#                    'global', domain.DomainName);
#            }
#        }
#
#        callback(null, results, source);
#    }