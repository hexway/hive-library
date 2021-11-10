import argparse
import os
from hive_library.rest import HiveRestApi
from hive_library import HiveLibrary
import socket
import yaml
from ipaddress import IPv4Address
from marshmallow.fields import UUID
from typing import Optional

help_desc = '''
Resolve 'noip' hostnmames in Hive project. At least trying.

python3 ./resolve_noip_hostnames.py -P 11111111-2222-47ff-5555-66666666

On a first run connection profile (server, username and password) will be stored at ~/.hive/config.yaml
'''

parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-s', '--server-url', help='Hive server URL')
parser.add_argument('-u', '--user', help='Hive username')
parser.add_argument('-p', '--password', help='Hive password')
parser.add_argument('-P', '--project', help='Hive project ID')

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

def resolve_hostmanes_without_ip():
    searchstring= 'ip == ""'
    print("querying filter: ", searchstring)
    search_result = hive_api.search(prj_id, search_string=searchstring)
    print("got some results: ", len(search_result))
    for host in search_result:
        #print (host.id)
        for hostname in host.names:
            #print (hostname.hostname, hostname.id)
            try:
                #print ("resolving hostname: ", hostname.hostname)
                resolved_ip = socket.gethostbyname(hostname.hostname)
                print (hostname.hostname, resolved_ip)

                hostnames_list =[]

                new_host: HiveLibrary.Host = HiveLibrary.Host()
                new_host.ip = IPv4Address(resolved_ip)

                hostnames_list.append(
                    HiveLibrary.Host.Name(
                        hostname=hostname.hostname,
                        # tags=[HiveLibrary.Tag(name="hostname_tag")],
                    )
                )
                new_host.names = hostnames_list

                task_id: Optional[UUID] = hive_api.create_host(project_id=prj_id, host=new_host)
                #print ("added")


            except Exception as e:
                #logging.error(traceback.format_exc())
                print ("Cant get IP for: ", hostname.hostname)


resolve_hostmanes_without_ip()