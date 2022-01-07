# AzureDatabricksDevopsConfiguration
This repository contains the IAAC specific code for Azure Databricks and post deployment configuration.

# AzureDatabricks
This repository contains all the scripts and templates that will help end to end provisioning of Databricks.

The ARM templates can be deployed using Azure CLI or Azure Devops Pipeline. The ARM Template files are the following:
dBricksTemplate.json
dbricksParameter.json

The powershell script does the following:
1. Creates cluster
2. Creates Workspace folder
3. Assignes cluster permissions to existing user groups.

The shell script does the following:
It provides workspace folder permissions to users. 

Both the above scripts will use 'databricks-params.json' file as input.
