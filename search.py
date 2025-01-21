#!/usr/bin/python3
import urllib3
import json
import csv
import sys

# Coded by Isaiah Stanke, licensed via GNU Public License v3.0

# Hardcoded API Key
AUTH_KEY = "ENTER API KEY HERE"

if len(sys.argv) < 2:
    print("Script to search ThreatFox for multiple IOCs (e.g. IPs, URLs, domains, file hashes) from a CSV file")
    print("Usage: python3 threatfox_search_ioc.py <csv-file>")
    quit()

# Get the CSV file path from the command-line arguments
csv_file = sys.argv[1]

# Set up the headers and connection pool
headers = {
    "Auth-Key": AUTH_KEY
}
pool = urllib3.HTTPSConnectionPool('threatfox-api.abuse.ch', port=443, maxsize=50, headers=headers)

# Load the IP addresses or other IOCs from the CSV file
try:
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        iocs = [row[0] for row in reader]  # Assume the first column contains the IOCs
except FileNotFoundError:
    print(f"Error: The file {csv_file} was not found.")
    quit()
except Exception as e:
    print(f"Error reading the file: {e}")
    quit()

print(f"Found {len(iocs)} IOCs to query. Starting ThreatFox queries...\n")

# Query ThreatFox for each IOC
for ioc in iocs:
    data = {
        'query': 'search_ioc',
        'search_term': ioc,
        'exact_match': True  # Ensure exact match results
    }
    json_data = json.dumps(data)
    try:
        response = pool.request("POST", "/api/v1/", body=json_data)
        response_data = response.data.decode("utf-8", "ignore")
        response_json = json.loads(response_data)
        
        print(f"Raw response for {ioc}: {response_json}")  # Debugging line to inspect response

        if response_json and "data" in response_json:
            if isinstance(response_json["data"], list):
                # Handle the case where data is a list of dictionaries
                print(f"Suspicious data for IOC {ioc}:")
                for entry in response_json["data"]:
                    if isinstance(entry, dict):
                        print(f"  - Malware Family: {entry.get('malware')}")
                        print(f"  - Confidence: {entry.get('confidence')}")
                        print(f"  - Description: {entry.get('comment')}")
                        print(f"  - First Seen: {entry.get('first_seen')}")
                        print(f"  - Last Seen: {entry.get('last_seen')}")
                    else:
                        print(f"  - Unexpected entry format (not a dictionary): {entry}")
            elif isinstance(response_json["data"], str):
                # Handle the case where data is a string
                print(f"No malicious data found for IOC {ioc}: {response_json['data']}")
            else:
                print(f"Unexpected data format for IOC {ioc}: {response_json['data']}")
        else:
            print(f"Unexpected response format for IOC {ioc}: {response_data}")
    except Exception as e:
        print(f"Error querying ThreatFox for IOC {ioc}: {e}")
    print("-" * 50)
