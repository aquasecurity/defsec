@minLength(3)
@maxLength(11)
param storagePrefix string = 'x'

param storageSKU string = '[Standard_LRS]'
param location string = resourceGroup().location

var uniqueStorageName = '${storagePrefix}${uniqueString(resourceGroup().id)}'

param moduleCount int = 2

module stgModule './module.bicep' = [for i in range(0, moduleCount): {
  name: '${i}deployModule'
  params: {
  }
}]

output storageName string = stgModule.outputs.storageName