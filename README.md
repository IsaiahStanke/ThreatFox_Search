# ThreatFox_Search
Search ThreatFox via list of IP Addresses

Hi! Thanks for checking this out, this a Python script I wrote that simply searches ThreatFox when giving a list of IP Addresses in the form of a .csv file. 
In order to run it, make sure you have the following libraries installed:

1. urllib3
2. json
3. csv
4. sys

Get an Auth-Key or API token from the ThreatFox dashboard and put it in the variable within the script called "AUTH_KEY" (it's hardcoded for ease of use but feel free to change as wanted).
Simply run it by doing the following:

"python search.py ips.csv"

It will only return exact matches, you can change that by setting the parameter "exact_match" as false within the data query. This script will tell you the following information:

1. Malware Family
2. Confidence Level
3. Description
4. First Seen
5. Last Seen

Thank you so much for checking this out! Spread it! 
