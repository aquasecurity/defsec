# METADATA
# title :"ACM Certificate Expiry"
# description: "Detect upcoming expiration of ACM certificates"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/acm/latest/userguide/managed-renewal.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ACM
#   severity: LOW
#   short_code: acm-certificate-expiry 
#   recommended_action: "Ensure AWS is able to renew the certificate via email or DNS validation of the domain."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            acm_certificate_expiry_pass: settings.acm_certificate_expiry_pass || this.settings.acm_certificate_expiry_pass.default,
#            acm_certificate_expiry_warn: settings.acm_certificate_expiry_warn || this.settings.acm_certificate_expiry_warn.default
#        };
#
#        var custom = helpers.isCustom(settings, this.settings);
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.acm, function(region, rcb){
#            var listCertificates = helpers.addSource(cache, source,
#                ['acm', 'listCertificates', region]);
#
#            if (!listCertificates) return rcb();
#
#            if (listCertificates.err || !listCertificates.data) {
#                helpers.addResult(results, 3,
#                    'Unable to list ACM certificates: ' + helpers.addError(listCertificates), region);
#                return rcb();
#            }
#
#            if (!listCertificates.data.length) {
#                helpers.addResult(results, 0, 'No ACM certificates found', region);
#                return rcb();
#            }
#
#            // Loop through certificates
#            listCertificates.data.forEach(function(cert){
#                var describeCertificate = helpers.addSource(cache, source,
#                    ['acm', 'describeCertificate', region, cert.CertificateArn]);
#
#                if (!describeCertificate || describeCertificate.err || !describeCertificate.data) {
#                    helpers.addResult(results, 3,
#                        'Unable to describe ACM certificate: ' + helpers.addError(describeCertificate), region, cert.CertificateArn);
#                } else if (!describeCertificate.data.Certificate || !describeCertificate.data.Certificate.NotAfter) {
#                    if (describeCertificate.data.Certificate &&
#                        describeCertificate.data.Certificate.RenewalEligibility &&
#                        describeCertificate.data.Certificate.RenewalEligibility == 'INELIGIBLE') {
#                        helpers.addResult(results, 1,
#                            'ACM certificate is not eligible for renewal', region, cert.CertificateArn);
#                    } else {
#                        helpers.addResult(results, 3,
#                            'ACM certificate does not have an expiration date configured', region, cert.CertificateArn);
#                    }
#                } else {
#                    var certificate = describeCertificate.data.Certificate;
#
#                    var then = new Date(certificate.NotAfter);
#                    var now = new Date();
#                    
#                    var difference = Math.round((new Date(then).getTime() - new Date(now).getTime())/(24*60*60*1000));
#                    var expiresInMsg = 'Certificate for domain: ' + certificate.DomainName + ' expires in ' + Math.abs(difference) + ' days';
#                    var expiredMsg = 'Certificate: for domain: ' + certificate.DomainName + ' expired ' + Math.abs(difference) + ' days ago';
#
#                    if (difference > config.acm_certificate_expiry_pass) {
#                        helpers.addResult(results, 0, expiresInMsg, region, certificate.CertificateArn, custom);
#                    } else if (difference > config.acm_certificate_expiry_warn) {
#                        helpers.addResult(results, 1, expiresInMsg, region, certificate.CertificateArn, custom);
#                    } else if (difference > 0) {
#                        helpers.addResult(results, 2, expiresInMsg, region, certificate.CertificateArn, custom);
#                    } else {
#                        helpers.addResult(results, 2, expiredMsg, region, certificate.CertificateArn, custom);
#                    }
#                }
#            });
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }