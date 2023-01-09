# METADATA
# title :"Domain Transfer Lock"
# description: "Ensures domains have the transfer lock set"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-transfer-from-route-53.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Route53
#   severity: LOW
#   short_code: domain-transfer-lock 
#   recommended_action: "Enable the transfer lock for the domain"
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
#            if (!domain.DomainName) continue;
#
#            // Skip .uk and .co.uk domains
#            if (domain.DomainName.indexOf('.uk') > -1) {
#                helpers.addResult(results, 0,
#                    'Domain: ' + domain.DomainName + ' does not support transfer locks',
#                    'global', domain.DomainName);
#            } else if (domain.TransferLock) {
#                helpers.addResult(results, 0,
#                    'Domain: ' + domain.DomainName + ' has the transfer lock enabled',
#                    'global', domain.DomainName);
#            } else {
#                helpers.addResult(results, 2,
#                    'Domain: ' + domain.DomainName + ' does not have the transfer lock enabled',
#                    'global', domain.DomainName);
#            }
#        }
#
#        callback(null, results, source);
#    }