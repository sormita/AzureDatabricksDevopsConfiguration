<#
.SYNOPSIS
  This script has functions to create post deployment configurations for Databricks.
.DESCRIPTION
  Following are the functions (in order of execution) performed by this script:
  1. Create KeyVault Scope for databaricks.
  2. Create Workspace folders.
  3. Create clusters: (i) Save clusterID in the keyvault as a secret.
                      (ii)Provide cluster permissions to pre-existing groups.


#Important Note: Before this script can be executed
#Please run Install-Module -Name Az -AllowClobber
#Otherwise this script will throw error

.EXAMPLE
$DatabricksConfigure = @{    
    ConfigurationJson = “\databricks-params.json”    
    workspaceName = “dbw-dev-aue-gteng”    
    keyVaultName = "kv-dev-aue-gteng"
    Environment = "dev"
}

\DatabricksProvisioning.ps1 @DatabricksConfigure


#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true, HelpMessage = "Is script executed from Pipeline")][bool]$isPipelineExec,	
	[Parameter(Mandatory = $true, HelpMessage = "Location of databricks-params.json file")][string]$ConfigurationJson,    
    [Parameter(Mandatory = $true, HelpMessage = "Databricks workspaceName")][string]$workspaceName,    
    [Parameter(Mandatory = $true, HelpMessage = "keyVaultName")][string]$keyVaultName,
    [Parameter(Mandatory = $true, HelpMessage = "Environment")][string]$Environment
)

############Class Definition##############

class ClusterSpecs{ 
[string]$cluster_name;
[string]$spark_version;
[string]$node_type_id;
[string]$driver_node_type_id;
[int]$autotermination_minutes;
#[bool]$enable_elastic_disk;
#[string]$cluster_source;
[string]$cluster_id;    
$autoscale=[ClusterAutoscaleSpecs]::new()
}

class ClusterAutoscaleSpecs{
 [int]$min_workers;
 [int]$max_workers;
}

 

class access_control_list{
 [string]$group_name;
 [string]$permission_level;
}

class cluster_group{
 $access_control_list;
}

class workspace_folders{
 $path;
}

class backend_azure_keyvault{
 $resource_id;
 $dns_name;
}

class azure_keyvault_scope{
 $scope;
 $scope_backend_type;
 $initial_manage_principal;
 $backend_azure_keyvault=[backend_azure_keyvault]::new()
}


###############Function Definition########################

Function GetConfigParams([bool]$isPipelineExec, $FilePath, $WorkspaceName, $KeyVaultName, $env)
{
 $subscriptionID=Get-AzSubscription
 $ResourceGroupResponse=Get-AzResourceGroup 
 $ResourceGroup=$ResourceGroupResponse.ResourceGroupName    
 
 #reading the parameters for this script from a json file
 $responseObject=Get-Content -Raw -Path $FilePath | ConvertFrom-Json

 $accessToken=GenerateToken $isPipelineExec $subscriptionID $ResourceGroup $WorkspaceName $DatabricksInstance $keyVaultName $env
 
 $headers=@{
  "Authorization"= "Bearer " + $accessToken.patToken;  
 } 
 

#CreateKeyVaultScope $keyVaultName $ResourceGroup $subscriptionID $keyVaultScopeName $accessToken.azToken $accessToken.mngmntToken $accessToken.DatabricksInstance
CreateWorkspaceFolders $responseObject $headers $accessToken.DatabricksInstance
CreateCluster $responseObject $headers $keyVaultName $accessToken.DatabricksInstance
}

#The following Rest API returns a malformed response.
Function GetDatabricksInstance ($azureMngmntToken, $subscriptionID, $resourceGroup, $workspaceName)
{
 Write-Host "-----Getting Databricks workspace URL--------------"
 $headers=@{
  "Authorization"= "Bearer " + $azureMngmntToken;  
 }
 $urlDBInstance="https://management.azure.com/subscriptions/"+ $subscriptionID +"/resourcegroups/" + $resourceGroup +"/providers/Microsoft.Databricks/workspaces/"+ $workspaceName +"?api-version=2018-04-01"

 $responseDB=Invoke-WebRequest $urlDBInstance -Method Get -Headers $headers
 
 ###The below string manipulation is done because 
 ###the above rest API is returning a malformed json
 ###which cannot be converted to object.
 $str1= $responseDB.Content |  Out-String 
 $sampleString="adb-XXXXXXXXXXXXXXXX.XX.azuredatabricks.net"
 $str2= $str1.Substring($str1.IndexOf("adb-"),$sampleString.Length)
 return $str2 
}

#This function will generate Azure AD Token
Function GenerateToken ($isPipelineExec, $subscriptionID, $resourceGroup, $workspaceName, $DatabricksInstance, $keyVaultName, $env)
{
    Write-Host "-----Getting Azure AD token and Management Token--------------"  

    if($isPipelineExec)
    {
     #################### Execute the below piece of code when executed from pipeline #########################
    
    $context= Get-AzContext

    $resource="2ff814a6-3304-4ab8-85cb-cd0e6f879c1d" #This is constant for Databricks
  
    #Generate Azure AD Token
    $adToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account,
    $context.Environment, 
    $context.Tenant.Id.ToString(), 
    $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $resource).AccessToken
    $azure_token= $adToken

    #Generate Management API Token
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $managementToken = $profileClient.AcquireAccessToken($context.Tenant.Id.ToString())
    $azure_mgmnt_token= $managementToken.AccessToken
        
    }
    else
    {
      #################### Execute the below piece of code to run the script from local #########################
        
      $ClientID = '<ApplicationID>'
      $TenantID = '<TenantID>'
      $ClientSecret = "<ClientSecret>"
      $Resource = '2ff814a6-3304-4ab8-85cb-cd0e6f879c1d'
              
    
      $TokenRequestParams = @{
      Method = 'POST'
      Uri    = "https://login.microsoftonline.com/$TenantID/oauth2/token"
      Body   = @{
        client_id = $ClientId
        resource  = $Resource
        grant_type= 'client_credentials'
        client_secret=$ClientSecret
      }
      }

      $TokenCodeRequest = Invoke-RestMethod @TokenRequestParams
      #Write-Host $TokenCodeRequest.access_token     
      $azure_token= $TokenCodeRequest.access_token

      $ManagementTokenRequest = @{
      Method = 'POST'
      Uri = "https://login.microsoftonline.com/" + $TenantID + "/oauth2/token"
      Body   = @{
        client_id = $ClientId
        resource  = "https://management.core.windows.net/"
        grant_type= 'client_credentials'
        client_secret=$ClientSecret
      }
      }

      $ManagementTokenCodeReq = Invoke-RestMethod @ManagementTokenRequest
      #Write-Host $ManagementTokenCodeReq.access_token
      $azure_mgmnt_token=$ManagementTokenCodeReq.access_token
    } 

    $DatabricksInstance=GetDatabricksInstance $azure_mgmnt_token $subscriptionID $resourceGroup $workspaceName

    GenerateDBPATToken $azure_token $azure_mgmnt_token $subscriptionID $resourceGroup $workspaceName $DatabricksInstance $keyVaultName $env    

}


Function GenerateDBPATToken ($azure_token, $azure_mgmnt_token, $subscriptionID, $resourceGroup, $workspaceName, $DatabricksInstance, $keyVaultName, $env)
{
 [hashtable]$access_token = @{}
 $access_token.azToken=$azure_token
 $access_token.mngmntToken=$azure_mgmnt_token
 
 $access_token.DatabricksInstance=$DatabricksInstance


 Write-Host "------Check if PAT exists-----------"
 $secretName=$kvsecretName='kvs-databricks-' + $env + 'auegteng'
 $secret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName -AsPlainText

 if($secret -eq $null)
 {
  Write-Host "-----Getting Databricks PAT Token--------------"
 
 $headers=@{
  "Authorization"= "Bearer " + $azure_token;
  "X-Databricks-Azure-SP-Management-Token" = $azure_mgmnt_token;
  "X-Databricks-Azure-Workspace-Resource-Id" = "/subscriptions/"+$subscriptionID+"/resourceGroups/" + $resourceGroup +"/providers/Microsoft.Databricks/workspaces/" + $workspaceName;
  }
      
  $PATTokenRequest = @{
    Method = 'POST'
    Uri = "https://" + $DatabricksInstance +"/api/2.0/token/create"
    Headers = $headers    
    }

 $dbPATTokenRequest=Invoke-RestMethod @PATTokenRequest
 $access_token.patToken=$dbPATTokenRequest.token_value
 }
 else
 {
  $access_token.patToken=$secret
 } 

 SavePatTokenKeyVault $keyVaultName $access_token.patToken $env

 return $access_token

}


<#
#This function will only work with Azure AAD Token
#This function is not unit tested as the author's ID
#do not have the required access as of now.
Function CreateKeyVaultScope($keyVaultName, $resourceGroup, $subscriptionID, $keyVaultScopeName, $azToken, $azMngmntToken, $DatabricksInstance)
{
      $ClientID = '<ApplicationID>'
      $TenantID = '<TenantID>'
      $username = "user.lastname@westernpower.com.au"
      $password = 'xxxxxxxxxxxx'
              
    
      $TokenRequestParams = @{
      Method = 'POST'
      Uri    = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
      Body   = @{
        grant_type = 'password'
        username  = $username
        password= $password
        scope='user.read%20openid%20profile%20offline_access'
        client_id = $ClientID
      }
      }

      $TokenCodeRequest = Invoke-RestMethod @TokenRequestParams
      #Write-Host $TokenCodeRequest.access_token     
      $azure_token= $TokenCodeRequest.access_token
 

 $headers=@{
  "Authorization"= "Bearer " + $azure_token;
  "X-Databricks-Azure-SP-Management-Token" = $azMngmntToken;
  "X-Databricks-Azure-Workspace-Resource-Id" = "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d";  
  }
 
 $backend_azure_keyvault=[backend_azure_keyvault]::new()
 $backend_azure_keyvault.resource_id="/subscriptions/" + $subscriptionID + "/resourceGroups/" + $resourceGroup + "/providers/Microsoft.KeyVault/vaults/" + $keyVaultName
 $backend_azure_keyvault.dns_name="https://"+$keyVaultName+ ".vault.azure.net/"

 $azure_keyvault_scope=[azure_keyvault_scope]::new()
 $azure_keyvault_scope.backend_azure_keyvault=$backend_azure_keyvault
 $azure_keyvault_scope.scope=$keyVaultScopeName
 $azure_keyvault_scope.scope_backend_type="AZURE_KEYVAULT"
 $azure_keyvault_scope.initial_manage_principal="users"

 $azureKeyVaultScopejson=$azure_keyvault_scope | ConvertTo-Json
 Write-Host $azureKeyVaultScopejson

 $urlKeyVaultScope="https://"+$DatabricksInstance+"/api/2.0/secrets/scopes/create"
 
 #initialize scope
 $responseReq=Invoke-WebRequest $urlKeyVaultScope -Method Post -Headers $headers -Body $azureKeyVaultScopejson -ContentType 'application/json'
 Write-Host $responseReq
}
#>

Function CreateWorkspaceFolders($responseObject, $headers, $DatabricksInstance)
{
 Write-Host "-------Entering function CreateWorkspaceFolders-------------"
 foreach($folder in $responseObject.folders)
 {
  $workspace_folder=[workspace_folders]::new() 
  $workspace_folder.path=$folder
  $wrkspceFolderJson=$workspace_folder | ConvertTo-Json
  Write-Host $wrkspceFolderJson
  
  $urlFolder="https://" + $DatabricksInstance + "/api/2.0/workspace/mkdirs"    
  #folders to be created
  Invoke-WebRequest $urlFolder -Method Post -Headers $headers -Body $wrkspceFolderJson -ContentType 'application/json'  
 }
}


Function CreateCluster($responseObject, $headers, $keyVaultName, $DatabricksInstance)
{
 Write-Host "-------Creating Clusters-------------"
  foreach($cluster in $responseObject.clusters)
 { 
  $cluster_specs=[ClusterSpecs]::new() 
  $cluster_specs.cluster_name= $cluster.cluster_specs_cluster_name  
  $cluster_specs.spark_version=$cluster.cluster_specs_spark_version
  $cluster_specs.node_type_id=$cluster.cluster_specs_node_type_id
  $cluster_specs.driver_node_type_id=$cluster.cluster_specs_driver_node_type_id
  $cluster_specs.autotermination_minutes=$cluster.cluster_specs_autotermination_minutes  
  $cluster_specs.autoscale.min_workers=$cluster.cluster_specs_autoscale_min_workers
  $cluster_specs.autoscale.max_workers=$cluster.cluster_specs_autoscale_max_workers
    
  $clusterString= $cluster_specs | ConvertTo-Json   
  $urlCluster="https://"+ $DatabricksInstance + "/api/2.0/clusters/create"
  
  #cluster is getting created
  $responseCluster=Invoke-WebRequest $urlCluster -Method Post -Headers $headers -Body $clusterString -ContentType 'application/json'| Select-Object -Expand Content|ConvertFrom-Json
  write-host "Cluster is getting created ClusterID: " $responseCluster.cluster_id

  SaveClusterIDKeyVault $keyVaultName $responseCluster.cluster_id $env

  #Assign cluster level permission to groups  
  AssignClusterGroupAccess $DatabricksInstance $responseObject.groups $cluster_specs.cluster_name $responseCluster.cluster_id
 }
 
}

Function SavePatTokenKeyVault($keyVaultName, $patToken, $env)
{
 Write-Host "-------Saving PAT Token to key vault-------------"
 $kvsecretName='kvs-databricks-' + $env + 'auegteng'
 $Expires = (Get-Date).AddYears(2).ToUniversalTime()
 $securedPatTokenValue = ConvertTo-SecureString -String $patToken -AsPlainText -Force
 
  #Set the cluster ID to a secret value in KeyVault
  Set-AzKeyVaultSecret -VaultName $keyVaultName -Name $kvsecretName -SecretValue $securedClusteIDValue -Expires $Expires  
}

Function SaveClusterIDKeyVault($keyVaultName, $cluster_id, $env)
{
 Write-Host "-------Saving clusterID to key vault-------------"
 $kvsecretName='kvs-databricks-clusterid-' + $env + 'auegteng' + $cluster_specs.cluster_name
 $Expires = (Get-Date).AddYears(2).ToUniversalTime()
 $securedClusteIDValue = ConvertTo-SecureString -String $cluster_id -AsPlainText -Force
 
  #Set the cluster ID to a secret value in KeyVault
  Set-AzKeyVaultSecret -VaultName $keyVaultName -Name $kvsecretName -SecretValue $securedClusteIDValue -Expires $Expires  
}

Function AssignClusterGroupAccess($DatabricksInstance, $groups, $cluster_name, $cluster_id)
{
 Write-Host "-------Assigning group policy access for cluster-------------"
 $access_control_collection = New-Object System.Collections.ArrayList
 [bool]$group_permission_provider

 foreach($group in $groups)
 {
  if($cluster_specs.cluster_name -eq  $group.cluster_name)
  {
   $group_permission_provider= $true
   foreach($permission in $group.permission_level)
   {   
    $access_control=[access_control_list]::new()
    $access_control.group_name=$group.group_name
    $access_control.permission_level=$permission
   
    $access_control_collection.Add($access_control) 
   }
  }
    
 }
  
 if($group_permission_provider)
 {
  $cluster_group=[cluster_group]::new()
  $cluster_group.access_control_list=$access_control_collection
  $cluster_groupjson=$cluster_group | ConvertTo-json
  

  #provide permissions to the group for the cluster
  $urlProvideGroupPermissions="https://"+ $DatabricksInstance +"/api/2.0/permissions/clusters/"+ $cluster_id  

  #it provides group access for a given cluster
  Invoke-WebRequest $urlProvideGroupPermissions -Method Patch -Headers $headers -Body $cluster_groupjson -ContentType 'application/json'
 }
 
}


##############Actual Execution Starts Here######################## 
  
  
  GetConfigParams $isPipelineExec $ConfigurationJson $workspaceName $keyVaultName $Environment

##############Actual Execution Ends Here#########################







