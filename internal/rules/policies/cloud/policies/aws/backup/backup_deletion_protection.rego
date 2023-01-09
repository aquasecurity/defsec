# METADATA
# title :"Backup Deletion Protection Enabled"
# description: "Ensure that an Amazon Backup vault access policy is configured to prevent the deletion of AWS backups in the backup vault."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/aws-backup/latest/devguide/creating-a-vault-access-policy.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Backup
#   severity: LOW
#   short_code: backup-deletion-protection 
#   recommended_action: "Add a statement in Backup vault access policy which denies global access to action: backup:DeleteRecoveryPoint"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.backup, function(region, rcb){
#            var listBackupVaults = helpers.addSource(cache, source,
#                ['backup', 'listBackupVaults', region]);
#
#            if (!listBackupVaults) return rcb();
#
#            if (listBackupVaults.err || !listBackupVaults.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for Backup vault list: ${helpers.addError(listBackupVaults)}`, region);
#                return rcb();
#            }
#
#            if (!listBackupVaults.data.length) {
#                helpers.addResult(results, 0, 'No Backup vaults found', region);
#                return rcb();
#            }
#
#            for (let vault of listBackupVaults.data){
#                if (!vault.BackupVaultArn || !vault.BackupVaultName) continue;
#               
#                let resource = vault.BackupVaultArn;
#
#                let getBackupVaultAccessPolicy = helpers.addSource(cache, source,
#                    ['backup', 'getBackupVaultAccessPolicy', region, vault.BackupVaultName]);
#
#                if (getBackupVaultAccessPolicy && getBackupVaultAccessPolicy.err && getBackupVaultAccessPolicy.err.code &&
#                        getBackupVaultAccessPolicy.err.code == 'ResourceNotFoundException') {
#                    helpers.addResult(results, 2,
#                        'No access policy found for Backup vault', region, resource);
#                    continue;
#                }
#    
#                if (!getBackupVaultAccessPolicy || getBackupVaultAccessPolicy.err || !getBackupVaultAccessPolicy.data) {
#                    helpers.addResult(results, 3, `Unable to get Backup vault access policy: ${helpers.addError(getBackupVaultAccessPolicy)}`, region, resource);
#                    continue;
#                }
#    
#                let statements = helpers.normalizePolicyDocument(getBackupVaultAccessPolicy.data.Policy);
#                let deleteProtected = false;
#
#                for (let statement of statements){  
#                    if (statement.Effect && statement.Effect.toUpperCase() === 'DENY' &&
#                        statement.Principal && helpers.globalPrincipal(statement.Principal) &&
#                        statement.Action && statement.Action.find(action => action.toUpperCase().includes('BACKUP:DELETERECOVERYPOINT'))) {
#                        deleteProtected = true;
#                    }
#                }
#
#                if (deleteProtected) {
#                    helpers.addResult(results, 0,
#                        'Backup vault has deletion protection enabled', region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Backup vault does not have deletion protection enabled', region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }