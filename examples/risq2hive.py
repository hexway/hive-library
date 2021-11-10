#!/usr/bin/python3
import json

from hive_library.rest import HiveRestApi
from typing import Optional, List
import os
from marshmallow.fields import UUID
import argparse
import yaml
import requests
from hive_library import HiveLibrary

help_desc = '''

Risq subdomains import from

GET /api/dns/passive/subdomains?query=domain.tld HTTP/1.1
Host: community.riskiq.com

python3 ./risq2hive.py -P 11111111-2222-47ff-5555-66666666 -f ./rskq_result.json

OR

python3 ./risq2hive.py -P 11111111-2222-47ff-5555-66666666 -d domain.tld -C [pts cookie value]

'''


###############################################


parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-s', '--server-url', help='Hive server URL')
parser.add_argument('-u', '--user', help='Hive username')
parser.add_argument('-p', '--password', help='Hive password')
parser.add_argument('-P', '--project', help='Project UUID')
parser.add_argument('-f', '--file', help='json file')
parser.add_argument('-d', '--domain', help='domain name')
parser.add_argument('-C', '--risq-pts-cookie', help='value of pts cookie on community.riskiq.com')

username: str = ""
password: str = ""
server: str = ""

inputfile=""
domain = ""
args = parser.parse_args()

if args.server_url:
    server: str = args.server_url
if args.user:
    username: str = args.user
if args.password:
    password: str = args.password
if args.project:
    prj_id = args.project
else:
    print("No Project ID specified! Use -P \n")
    exit()
if args.file:
    inputfile = args.file

else:

    if args.domain:
        domain = args.domain
        if args.risq_pts_cookie:
            pts_cookie = args.risq_pts_cookie
        else:
            print("No PTS cookie value specified!\nlogin to community.riskiq.com then provide a pts cookie with -C\n")
            exit()


    else:
        print("No input file or target domain specified! Use -f or -d\n")
        exit()

if (not args.password) or (not args.user) or (not args.server_url):
    print("Trying to use connection info from config file")
    if os.path.isfile(os.path.expanduser("~/.hive/config.yaml")):
        print("~/.hive/config.yaml detected")
        conf_file = open(os.path.expanduser("~/.hive/config.yaml"), 'r')
        config = yaml.safe_load(conf_file)

        server: str = config['server']
        print("Using Hive server: " + server)
        username: str = config['username']
        password: str = config['password']

if not password:
    print("Hive password not specified! Use -p")
    exit()

if not username:
    print("Hive username not specified! Use -u")
    exit()
if not server:
    print("Hive server not specified! Use -s")
    exit()



###########################################

# Connect to Hive and store provided creds to config at ~/.hive/config.yaml
hive_api: HiveRestApi = HiveRestApi(username=username, password=password, server=server, debug=True)

if inputfile:
    with open(inputfile, encoding='utf-8') as json_file:
        riskqdata = json.load(json_file)

if domain:
    cookies = {'pts': pts_cookie}
    r = requests.get('https://community.riskiq.com/api/dns/passive/subdomains?query='+domain, cookies=cookies )
    riskqdata = json.loads(r.text)



uniq_records = []
wildcard_records = []
for result in riskqdata['results']:
    hostname = result["hostname"]
    if "*" in hostname:
        #print (hostname[2:])
        wildcard_records.append(hostname[2:])

#print (wildcard_records)

def is_wildcard(hostname):
    for wildcard in wildcard_records:
        if wildcard in hostname:
            return True
    return False

hostnames = []
hostnames_list = []
new_host: HiveLibrary.Host = HiveLibrary.Host()

print("Uploading hostnames to Hive")

for result in riskqdata['results']:
    hostname = result["hostname"]
    if is_wildcard(hostname):
        continue

    print (hostname)
    hostnames_list.append(
            HiveLibrary.Host.Name(
                hostname=hostname,
                # tags=[HiveLibrary.Tag(name="hostname_tag")],
            )
        )
#ip = socket.gethostbyname(hostname)
#current_host = IPv4Address(ip)
new_host.ip = None
new_host.names = hostnames_list
task_id: Optional[UUID] = hive_api.create_host(project_id=prj_id, host=new_host)

