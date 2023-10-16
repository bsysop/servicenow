#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
import argparse
import requests
import json
import re

def check_vulnerability(url, g_ck_value, cookies):
    table_list = [
        "t=cmdb_model&f=name",
        "t=cmn_department&f=app_name",
        "t=kb_knowledge&f=text",
        "t=licensable_app&f=app_name",
        "t=alm_asset&f=display_name",
        "t=sys_attachment&f=file_name",
        "t=sys_attachment_doc&f=data",
        "t=oauth_entity&f=name",
        "t=cmn_cost_center&f=name",
        "t=cmdb_model&f=name",
        "t=sc_cat_item&f=name",
        "t=sn_admin_center_application&f-name",
        "t=cmn_company&f=name",
        "t=sys_email_attachment&f=email",
        "t=sys_email_attachment&f=attachment",
        "t=cmn_notif_device&f=email_address",
        "t=sys_portal_age&f=display_name",
        "t=incident&f=short_description"
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

        post_url = f"{url}/api/now/sp/widget/widget-simple-list?{table}"
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
