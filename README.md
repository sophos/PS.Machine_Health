# Sophos_Central_Machine_Health
This will create a health report for every machines in an MSP/EDB/Single Sophos Central console
Please follow the PDF guide
This script replaces the previous scripts Endpoint_Health_EDB_MSP and Endpoint_Health_Single_Tenant scripts into one script
Alerts have also been added to the report
The config file allows other data to be added to the report as required

v2024.12
This version needs a new config file
Changed to a new versioning scheme
Fixed an issue where all machines would be reported even if only broken machines was seletected
Added the option to report on machines in Adaptive Attack Protection. This is in beta. It slows the script down a lot, seriously, a lot. This is why the new config file is required.

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

v2.46
Fixed an issue where the sub estate names would be incorrect
Added the option to only report on machines with issues. This includes, bad service health and bad threat health as well as general health
Fixed an issue where machines with strange characters in the hostname (inlcuding emoji's) would look wrong in the report. The application reading the file needs to support these character. Excel by default does not. Apple Numbers is an application that does
Colour has been added to the console. Run the script via PowerShell to see the colour
The service order has been changed to reflect the new modern Endpoint services. These are now at the beginning

v2.50
Added the new Endpoint services
Added the ability for MSP and EDB customers to turn on a menu that will list all the consoles and run a report on a single one

v2.52
Fixed an issue when the SophosCBR service was present

v2.66
The Endpoint column has been removed. This is no longer requried as you can't install Intercept X without AV
Add the ability to report on machines in certain groups - This requires the new config file
Renamed the MTR column to MDR
Fixed an issue where if the services option was used and the machines were very old, the script would crash
