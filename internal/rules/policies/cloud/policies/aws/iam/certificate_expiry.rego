# METADATA
# title :"Certificate Expiry"
# description: "Detect upcoming expiration of certificates used with ELBs"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-update-ssl-cert.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: certificate-expiry 
#   recommended_action: "Update your certificates before the expiration date"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            certificate_expiry_pass: settings.certificate_expiry_pass || this.settings.certificate_expiry_pass.default,
#            certificate_expiry_warn: settings.certificate_expiry_warn || this.settings.certificate_expiry_warn.default
#        };
#
#        var custom = helpers.isCustom(settings, this.settings);
#
#        var results = [];
#        var source = {};
#
#        var region = helpers.defaultRegion(settings);
#
#        var listServerCertificates = helpers.addSource(cache, source,
#            ['iam', 'listServerCertificates', region]);
#
#        if (!listServerCertificates) return callback(null, results, source);
#
#        if (listServerCertificates.err || !listServerCertificates.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for certificates: ' + helpers.addError(listServerCertificates));
#            return callback(null, results, source);
#        }
#
#        if (!listServerCertificates.data.length) {
#            helpers.addResult(results, 0, 'No certificates found');
#            return callback(null, results, source);
#        }
#
#        var now = new Date();
#
#        for (var i in listServerCertificates.data) {
#            if (listServerCertificates.data[i].ServerCertificateName && listServerCertificates.data[i].Expiration) {
#                var certificate = listServerCertificates.data[i];
#
#                var then = new Date(certificate.Expiration);
#                
#                var difference = helpers.daysBetween(then, now);
#                var expiresInMsg = 'Certificate: ' + certificate.ServerCertificateName + ' expires in ' + Math.abs(difference) + ' days';
#                var expiredMsg = 'Certificate: ' + certificate.ServerCertificateName + ' expired ' + Math.abs(difference) + ' days ago';
#
#                // Expired already
#                if (then < now) {
#                    helpers.addResult(results, 2, expiredMsg, 'global', certificate.Arn);
#                } else {
#                    // Expires in the future
#                    if (difference > config.certificate_expiry_pass) {
#                        helpers.addResult(results, 0, expiresInMsg, 'global', certificate.Arn, custom);
#                    } else if (difference > config.certificate_expiry_warn) {
#                        helpers.addResult(results, 1, expiresInMsg, 'global', certificate.Arn, custom);
#                    } else if (difference > 0) {
#                        helpers.addResult(results, 2, expiresInMsg, 'global', certificate.Arn, custom);
#                    } else {
#                        helpers.addResult(results, 0, expiredMsg, 'global', certificate.Arn, custom);
#                    }
#                }
#            }
#        }
#
#        callback(null, results, source);
#    }