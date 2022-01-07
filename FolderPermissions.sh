#For this script to work successfully 'jq' library has to be installed.
#
#Sample run statement:
#sh Folderpermissions.sh "adb-1164159897702681.1.azuredatabricks.net" 'dapi0a41bbba576a1d0fa2b16628d85e7c72-3' #"C:\CodeBase\ShellScriptDevelopment\directories.json"
#
#Important Note: 'directories.json' should not have any space between literals.
#
#eg directories.json:
#{"objects":[{"object_type": "DIRECTORY","path": "/Users","object_id": 351133617530280},{"object_type": "DIRECTORY","path": "/Shared","object_id": #351133617530281},{"object_type": "DIRECTORY","path": "/Repos","object_id": 351133617530284},{"object_type": "DIRECTORY","path": #"/FutureGrid","object_id": 351133617530288},{"object_type": "DIRECTORY","path": "/Util","object_id": 351133617530289},{"object_type": #"DIRECTORY","path":"/UnitTesting","object_id": 351133617530290}]}
#
#


#arguments
databricks_instance="adb-xxxxxxxxxxxxxxxxx.x.azuredatabricks.net"
patToken='dapixxxxxxxxxxxxxxxxxxxxxxx-x'
url_getDirectoryID='https://'$databricks_instance'/api/2.0/workspace/list'
jsonFilepath="C:\CodeBase\ShellScriptDevelopment\directories.json"
echo $patToken
#Get the directory IDs
curl --location --request GET $url_getDirectoryID \
--header 'Authorization: Bearer dapi701bd765396b407088d87be9d4918e7e-3' \
--header 'Content-Type: application/json' \
--data-raw '{"path": "/"}' -o $jsonFilepath


#provide permissions for the directories mentioned in databricks-params file
for k in $(jq '.folderAccess[].id' databricks-params.json | tr -d '\r');
do 
   
   folderjson=$(jq -r '.folderAccess[] | select(.id=='$k')' databricks-params.json | tr -d '\r');
   
   folder_name=$(jq -r '.folder_name' <<< "$folderjson")
   
   object_idjson=$(jq -r '.objects[] | select(.path=="'$folder_name'")' directories.json | tr -d '\r')
   
   object_id=$(jq '.object_id' <<< "$object_idjson")
      
   group_name=$(jq -r '.group_name' <<< "$folderjson")
   echo $group_name
   dir_permissionjson=$(jq -r '.permission_level' <<< "$folderjson" | tr -d '\r')
   
   
   for q in $(jq -r '.[]' <<< "$dir_permissionjson" | tr -d '\r');
   do
     
	 if [[ "$q" != "]" &&  "$q" != "[" ]];
	 then
       if [ ! -z "$object_id" ];
       then
	    JSON_STRING="{\"access_control_list\": [{\"group_name\":\"$group_name\",\"permission_level\":\"$q\"}]}"
        echo $q	
        #echo $contentLength	
        url='https://$databricks_instance/api/2.0/permissions/directories/'$object_id
	    echo $JSON_STRING
				
		curl --location --request PATCH $url \
        --header 'Authorization: Bearer $patToken' \
        --header 'Content-Type: application/json' \
        --data-raw '{"access_control_list": [{"group_name":"'$group_name'","permission_level":"'$q'"}]}'

       fi	   
	   
	 fi
   done
   
done




