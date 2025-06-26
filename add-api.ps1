#Use this to add the API keys to Environment Variables needed for IOC-Lookup.py
#This will ensure that the Environment Variable names match what IOC-Lookup.py is looking for
#Replace the first argument in SetEnvironmentVariable to the key you have for each service.
#For example, for AbuseIPDB you would replace 'abdb_key' with your key.

#command to execute: powershell -noexit -ExecutionPolicy Bypass -File .\add-api.ps1


#ABUSEIPDB
#Sign-up link: https://www.abuseipdb.com/register?plan=free
#To find API key use Create Key on this page: https://www.abuseipdb.com/account/api
Write-Output "Adding AbuseIPDB Key"
[System.Environment]::SetEnvironmentVariable('abdb_key','change',[System.EnvironmentVariableTarget]::User)

#VIRUSTOTAL
#Sign-up link: https://www.virustotal.com/gui/join-us
#To find API key go to menu in top right and select API Key and use the 'eye' button to reveal
Write-Output "Adding VirusTotal Key"
[System.Environment]::SetEnvironmentVariable('vt_key','change',[System.EnvironmentVariableTarget]::User)

#IPQS
#Sign-up link: https://www.ipqualityscore.com/create-account
#To find API key use the 'eye' button to reveal on this page: https://www.ipqualityscore.com/user/settings
Write-Output "Adding IPQS Key"
[System.Environment]::SetEnvironmentVariable('ipqs_key','change',[System.EnvironmentVariableTarget]::User)

#SHODAN
#Sign-up link: https://account.shodan.io/register
#To find API key use the 'Show' button to reveal on this page: https://account.shodan.io
Write-Output "Adding Shodan Key"
[System.Environment]::SetEnvironmentVariable('shodan_key','change',[System.EnvironmentVariableTarget]::User)

Write-Output "All keys added"