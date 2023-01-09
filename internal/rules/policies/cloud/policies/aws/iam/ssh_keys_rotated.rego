# METADATA
# title :"SSH Keys Rotated"
# description: "Ensures SSH keys are not older than 180 days in order to reduce accidental exposures"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_ssh-keys.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: ssh-keys-rotated 
#   recommended_action: "To rotate an SSH key, first create a new public-private key pair, then upload the public key to AWS and delete the old key."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            ssh_keys_rotated_fail: settings.ssh_keys_rotated_fail || this.settings.ssh_keys_rotated_fail.default,
#            ssh_keys_rotated_warn: settings.ssh_keys_rotated_warn || this.settings.ssh_keys_rotated_warn.default
#        };
#
#        var results = [];
#        var source = {};
#
#        var region = helpers.defaultRegion(settings);
#
#        var listUsers = helpers.addSource(cache, source,
#            ['iam', 'listUsers', region]);
#
#        if (!listUsers) return callback(null, results, source);
#
#        if (listUsers.err || !listUsers.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for Users: ' + helpers.addError(listUsers));
#            return callback(null, results, source);
#        }
#
#        if (!listUsers.data.length) {
#            helpers.addResult(results, 0, 'No iam users found', 'global');
#        } 
#
#        for (var user of listUsers.data) {
#            if (!user.UserName) continue;
#            
#            var found = false;
#            var listSSHPublicKeys = helpers.addSource(cache, source,
#                ['iam', 'listSSHPublicKeys', region, user.UserName]);
#
#            if (!listSSHPublicKeys || listSSHPublicKeys.err || !listSSHPublicKeys.data || !listSSHPublicKeys.data.SSHPublicKeys) {
#                helpers.addResult(results, 3,
#                    'Unable to query for SSH Keys: ' + helpers.addError(listSSHPublicKeys), user.Arn);
#                continue;
#            }
#
#            for (var sshkey of listSSHPublicKeys.data.SSHPublicKeys) {
#
#                if (sshkey.Status && sshkey.Status ==='Active') {
#                    if (!sshkey.UploadDate) continue;
#                    
#                    var keyDate = new Date(sshkey.UploadDate);
#                    var daysOld = helpers.daysAgo(keyDate);
#                    var returnMsg = `SSH key with ID: ${sshkey.SSHPublicKeyId} is ${daysOld} days old`;
#
#                    if (daysOld > config.ssh_keys_rotated_fail) {
#                        helpers.addResult(results, 2, returnMsg, 'global', user.Arn);
#
#                    } else if (daysOld > config.ssh_keys_rotated_warn) {
#                        helpers.addResult(results, 1, returnMsg, 'global', user.Arn);
#
#                    } else {
#                        helpers.addResult(results, 0, returnMsg, 'global', user.Arn);
#                    }
#                    found = true;
#                }      
#            }    
#            if (!found) {
#                helpers.addResult(results, 0, 'No SSH keys found', 'global', user.Arn);
#            }        
#        }
#        callback(null, results, source);
#    }