#!/usr/bin/env python3
import requests
import json
from datetime import datetime
import argparse
from argparse import RawTextHelpFormatter
import sys
import re

api_key = 'your_api_key_here'
client_id = 'your_client_id_here'
client_token = 'your_client_token_here'

version = "0.7"
default_scopes = "epo.evt.r"
base_url = 'https://api.manage.trellix.com'


def trellix_api_auth(key=api_key, id=client_id, token=client_token, scopes=default_scopes):
    iam_url = "https://iam.mcafee-cloud.com/iam/v1.1/token"

    session = requests.Session()

    headers = {
        'x-api-key': key,
        'Content-Type': 'application/vnd.api+json'
    }

    auth = (id, token)

    payload = {
        "grant_type": "client_credentials",
        "scope": scopes
    }

    res = session.post(iam_url, headers=headers, auth=auth, data=payload)

    if res.ok:
        access_token = res.json()['access_token']
        headers['Authorization'] = 'Bearer ' + access_token
        session.headers.update(headers)
        return session
    else:
        print("Error getting IAM token: {0} - {1}".format(res.status_code, res.text))
        exit()


def open_trellix_session():
    return trellix_api_auth(scopes="ins.user ins.suser ins.ms.r")


def close_trellix_session(session):
    session.close()


def get_campaigns(session, keyword=''):
    if keyword == 'all':
        keyword = ''
    filters = {
        'limit': 3000,
        'filter[name][like]': keyword
    }
    campaigns = session.get(base_url + '/insights/v2/campaigns', params=filters)
    print("Found {} records".format(len(json.loads(campaigns.text)["data"])))
    return json.loads(campaigns.text)["data"]

def bytes_to_kilobytes(bytes):
    kilobytes = bytes / 1024
    return str(round(kilobytes,2)) + "KB"

def get_artefacts(session, artefact, type):
    filters = {
        'hashtype': type,
        'hashvalue': artefact,
        'fields': 'campaigns'
    }
    artefact_info = session.get(base_url + '/insights/v2/artefacts/files', params=filters)
    artefact_json=json.loads(artefact_info.text)
    #print("\nResult: {}\n".format(artefact_info.text))
    id = artefact_json[artefact]["data"]["attributes"]["id"]
    if id != "md5-undefined":
        class_name = artefact_json[artefact]["data"]["attributes"]["classification-name"]
        class_type = artefact_json[artefact]["data"]["attributes"]["classification-type"]
        size = artefact_json[artefact]["data"]["attributes"]["file-size"]
        first_seen = artefact_json[artefact]["data"]["attributes"]["first-seen"]
        relations = artefact_json[artefact]["included"]
        print("size: {}".format(bytes_to_kilobytes(size)))
        print("first seen: {}".format(datetime.fromtimestamp(first_seen)))
        print("Reputation: {}".format(class_type))
        print("Name: {}".format(class_name))
        print("Relationships:")
        print("{:<36} | {:<10}".format('ID', 'Campaign or Profile'))
        for relation in relations:
            print("{} - {}".format(relation['id'],relation['attributes']['name']))
    else:
        print("Artefact not found")
    return artefact_info


def get_iocs(session, campaign_id):
    iocs = session.get(base_url + '/insights/v2/campaigns/' + campaign_id + '/iocs')
    return iocs.text


def display_iocs(iocs, format, type=["md5", "sha1", "sha256", "ip", "url", "domain"]):
    parsed_iocs = []
    iocs = json.loads(iocs)
    for ioc in iocs["data"]:
        if ioc["attributes"]["type"] in type:
            if format == "full":
                parsed_iocs.append(ioc["attributes"]["type"] +":" + ioc["attributes"]["value"] + " ||| Comment:" + (ioc["attributes"]["comment"]).replace("\n", "").replace("\r", "") + "\n")
            else:
                parsed_iocs.append(ioc["attributes"]["value"])
                if format=="kibana":
                    parsed_iocs.append(" OR ")
                if format=="list":
                    parsed_iocs.append("\n")

    print("".join(parsed_iocs[:-1]))


def get_galaxies(session, campaign_id):
    def get_tools(galaxies):
        parsed_tools = []
        tools = json.loads(galaxies)
        for tool in tools["data"]:
            if tool["attributes"]["category"] == "trellix-tool":
                parsed_tools.append(tool["attributes"]["name"])
        return parsed_tools

    def get_mitres(galaxies):
        parsed_mitres = []
        mitres = json.loads(galaxies)
        for mitre in mitres["data"]:
            if mitre["attributes"]["category"] == "mitre-attack-pattern":
                parsed_mitres.append(mitre["attributes"]["name"])
        return parsed_mitres

    def get_target(galaxies):
        parsed_targets = []
        targets = json.loads(galaxies)
        for target in targets["data"]:
            if target["attributes"]["category"] == "target-information":
                parsed_targets.append(target["attributes"]["name"])
        return parsed_targets

    galaxies = session.get(base_url + '/insights/v2/campaigns/' + campaign_id + '/galaxies')
    galaxies = galaxies.text
    return {'mitre': get_mitres(galaxies), 'tools': get_tools(galaxies)}


def display_tools(galaxies):
    print("TOOLS:")
    for tool in galaxies['tools']:
        print(tool)
    print("-" * 20)


def display_mitre(galaxies):
    print("MITRE TECHNIQUES:")
    for mitre in galaxies['mitre']:
        print(mitre)
    print("-" * 20)


def sort_by_datetime_key(list_of_dicts, key):
    sorted_list = sorted(list_of_dicts, key=lambda x: datetime.strptime(x[key], "%Y-%m-%dT%H:%M:%S.%fZ"), reverse=True)
    return sorted_list


def sort_campaigns_id_by_time(campaigns, criteria="created-on"):
    # criteria="created-on" or criteria="updated-on"
    print("Sorted by datetime: {}".format(criteria))
    parsed_campaigns = []
    for campaign in campaigns:
        parsed_campaign = {}
        parsed_campaign['created-on'] = campaign["attributes"]['created-on']
        parsed_campaign['updated-on'] = campaign["attributes"]['updated-on']
        parsed_campaign['id'] = campaign["id"]
        parsed_campaign['name'] = campaign["attributes"]["name"]
        parsed_campaign['threat-level-id'] = campaign["attributes"]["threat-level-id"]
        parsed_campaigns.append(parsed_campaign)
    return sort_by_datetime_key(parsed_campaigns, criteria)


def display_campaigns(campaigns, limit, sort_criteria='created-on'):
    campaigns = sort_campaigns_id_by_time(campaigns, sort_criteria)
    campaigns = campaigns[:limit]
    threat_level = {1: 'High', 2: 'Medium', 3: 'Low'}
    print("View limited to {} records".format(limit))

    if sort_criteria == 'created-on':
        print("*{:<9} | {:<10} | {:<36} | {:<6} | {:<32}".format('Created', 'Updated', 'Id', 'Level', 'Name'))
    if sort_criteria == 'updated-on':
        print("{:<10} | *{:<9} | {:<36} | {:<6} | {:<32}".format('Created', 'Updated', 'Id', 'Level', 'Name'))
    maxlength_name = 60
    for campaign in campaigns:
        if len(campaign["name"]) > maxlength_name:
            campaign["name"] = campaign["name"][:maxlength_name + 5] + "..."
        if campaign['created-on'] == campaign['updated-on']:
            campaign['updated-on'] = ' ' * 10
        else:
            campaign['updated-on'] = datetime.strptime(campaign['updated-on'], "%Y-%m-%dT%H:%M:%S.%fZ").strftime(
                "%Y-%m-%d")
        campaign['created-on'] = datetime.strptime(campaign['created-on'], "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d")
        print("{:<10} | {:<10} | {:<35} | {:<6} | {:<72}"
              .format(campaign['created-on'], campaign['updated-on'], campaign['id'],
                      threat_level[campaign['threat-level-id']], campaign['name']))


def is_hash(keyword):
    # Check if the string matches the MD5 pattern
    if re.match(r'^[a-fA-F0-9]{32}$', keyword):
        return 'md5'

    # Check if the string matches the SHA1 pattern
    if re.match(r'^[a-fA-F0-9]{40}$', keyword):
        return 'sha1'

    # Check if the string matches the SHA256 pattern
    if re.match(r'^[a-fA-F0-9]{64}$', keyword):
        return 'sha256'

    return False


def is_ipv4(keyword):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, keyword):
        octets = keyword.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            print("Found ip")
            return True
    return False


def is_domain(keyword):
    pattern = r'^([a-zA-Z0-9-]+\.){1,}[a-zA-Z]{2,}$'
    if re.match(pattern, keyword):
        print("Found domain")
        return True
    return False


def is_url(keyword):
    pattern = r'^(http|https|ftp)://[^\s/$.?#].[^\s]*$'
    if re.match(pattern, keyword):
        print("Found url")
        return True
    return False


def is_ioc(keyword):
    if is_hash(keyword) or is_ipv4(keyword) or is_domain(keyword) or is_url(keyword):
        return True
    else:
        return False

text = "Insights CL v" + version + "- A Trellix Insights command line tool - Community Project\nexamples of usage:\n " \
                                   "insightsCL.py " \
                                   "--search apt29\n insightsCL.py --search all --sortby updated-on --limit 5\n " \
                                   "insightsCL.py --search 1ef9c42efe6e9a08b7ebb16913fa0228\n insightsCL.py " \
                                   "--get-info 6c2ef20f-7c2c-417c-8f5e-73e4b9936a72\n " \
                                   "insightsCL.py --get-iocs 6c2ef20f-7c2c-417c-8f5e-73e4b9936a72\n insightsCL.py " \
                                   "--get-iocs 6c2ef20f-7c2c-417c-8f5e-73e4b9936a72 --ioc-type domain"
parser = argparse.ArgumentParser(description=text, formatter_class=RawTextHelpFormatter)
parser.add_argument('--search', dest='keyword', type=str, help='search | values:["keyword","all", "type:md5", "type:sha256"]',
                    default=False)
parser.add_argument('--sortby', dest='sortby', type=str, help='sort results from search Campaigns | values:[created-on|updated-on]', default="created-on")
parser.add_argument('--limit', dest='limit', type=int, help='number of results | default: 10', default=10)
parser.add_argument('--get-iocs', dest='campID', type=str, help='get IOCs | arg ex. 6c2ef20f-7c2c-417c-8f5e-73e4b9936a72', default=False)
parser.add_argument('--ioc-type', dest='ioctype', type=str, help='IOC type | values:["md5","sha256", "ip", "url", "domain"]',
                    default=False)
parser.add_argument('--get-info', dest='IDcamp', type=str, help='get Tools and MITRE | arg ex. 6c2ef20f-7c2c-417c-8f5e-73e4b9936a72', default="")
parser.add_argument('--output', dest='format', type=str, help='IOCs print format | values:["list","kibana","full"]', default="list")
args = parser.parse_args()

if len(sys.argv) == 1:
    parser.print_help()

if args.keyword:
    type_artefact = is_hash(args.keyword)
    if type_artefact:
        if type_artefact=='sha1':
            print("SHA1 not supported")
            exit()
        session = open_trellix_session()
        get_artefacts(session,args.keyword,type_artefact)
        close_trellix_session(session)
    else:
        sortby_options = ['created-on', 'updated-on', '']
        if args.sortby in sortby_options:
            session = open_trellix_session()
            campaigns = get_campaigns(session, args.keyword)
            display_campaigns(campaigns, args.limit, args.sortby)
            close_trellix_session(session)
        else:
            parser.print_help()

if args.IDcamp:
    if len(args.IDcamp) == 36:
        session = open_trellix_session()
        galaxies = get_galaxies(session, args.IDcamp)
        display_tools(galaxies)
        display_mitre(galaxies)
        close_trellix_session(session)
    else:
        parser.print_help()

if args.campID:
    if len(args.campID) == 36:
        session = open_trellix_session()
        iocs = get_iocs(session, args.campID)
        if args.ioctype:
            display_iocs(iocs, args.format, args.ioctype)
        else:
            display_iocs(iocs, args.format)
        close_trellix_session(session)
    else:
        parser.print_help()
