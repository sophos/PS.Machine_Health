# Sophos_Central_Machine_Health
This will create a health report for every machines in an MSP/EDB/Single Sophos Central console
Please follow the PDF guide
This script replaces the previous scripts Endpoint_Health_EDB_MSP and Endpoint_Health_Single_Tenant scripts into one script
Alerts have also been added to the report
The config file allows other data to be added to the report as required

v2.20
Fixed an issue when the script was run against a Sophos Central Enterprise Dashboard

v2.31
Fixed an issue where alerts could be over reported
Added the functionality to generate a report per sub estate rather than one big report

v2.36
Added a timer to report how long the report takes
Fixed an issue where some alerts could be missed

v2.40
Fixed an issue where you could see an XDR or item error
Added the option to add the sub estate ID to the report

v2.41
Fixed an issue where under some circumstances Alerts would get a 403 error
