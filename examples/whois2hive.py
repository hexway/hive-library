import argparse
import os
from hive_library.rest import HiveRestApi
from ipwhois import IPWhois

import yaml

help_desc = '''
WHOIS 2 hive 

Get Whois for all IPs from Hive project and tag them with Net names:

python3 ./whois2hive.py -P 11111111-2222-47ff-5555-66666666

On a first run connection profile (server, username and password) will be stored at ~/.hive/config.yaml
'''

parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-s', '--server-url', help='Hive server URL')
parser.add_argument('-u', '--user', help='Hive username')
parser.add_argument('-p', '--password', help='Hive password')
parser.add_argument('-P', '--project', help='get project list')

username: str = ""
password: str = ""
server: str = ""


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

if (not args.password) or (not args.user) or (not args.server_url):
    print("Trying to use connection info from config file")
    if os.path.isfile(os.path.expanduser("~/.hive/config.yaml")):
        print("~/.hive/config.yaml detected")
        conf_file = open(os.path.expanduser("~/.hive/config.yaml"), 'r')
        config = yaml.safe_load(conf_file)

        server: str = config['server']
        print("Using Hive server: "+server)
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

# Connect to Hive and store provided creds to config at ~/.hive/config.yaml
hive_api: HiveRestApi = HiveRestApi(username=username, password=password, server=server, debug=True)

ip_list = hive_api.get_ip_labels_for_project(project_id=prj_id)
for ip in ip_list:
    print (ip)
    whois = IPWhois(ip.label)
    whois_result = whois.lookup_whois()
    for net in whois_result['nets']:
       if net['name'] is not None:
           #print (net['name'])
           #print(net['description'])
           hive_api.create_tag(tag_name=net['name'], node_id= ip.id, project_id=prj_id)
