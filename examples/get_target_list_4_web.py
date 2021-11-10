import argparse
import os
from hive_library.rest import HiveRestApi
import yaml


help_desc = '''
Gets all http and https services from Hive, combining with all assigned hostnames and IPs.
As Result you will have a target list to feed into nuclei/GoWitness/Whatweb/dirsearh etc.

It based on services described at Hive so dont foget ask Nmap to detect them while scanning.

python3 ./get_target_list_4_web.py -P 11111111-2222-47ff-5555-66666666 > targets_web.list

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
    #print("Trying to use connection info from config file")
    if os.path.isfile(os.path.expanduser("~/.hive/config.yaml")):
        #print("~/.hive/config.yaml detected")
        conf_file = open(os.path.expanduser("~/.hive/config.yaml"), 'r')
        config = yaml.safe_load(conf_file)

        server: str = config['server']
        #print("Using Hive server: "+server)
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



#############################


# Connect to Hive and store provided creds to config at ~/.hive/config.yaml
hive_api: HiveRestApi = HiveRestApi(username=username, password=password, server=server)
#hive_api: HiveRestApi = HiveRestApi(username=username, password=password, server=server, debug=True, proxy="http://127.0.0.1:8080")


def get_target_list_4_web():
    # get all plain HTTP services first
    searchstring= 'service == "http" or service == "http-%"'
    #print("querying filter: ", searchstring)
    search_result = hive_api.search(prj_id, search_string=searchstring)
    #print("got some results: ", len(search_result))
    for host in search_result:
        #print (host.id)
        for port in host.ports:
            print ("http://"+str(host.ip)+":"+str(port.port))
            for hostname in host.names:
                # skip wildcard hostnames
                if "*." in hostname.hostname:
                    continue
                print ("http://"+str(hostname.hostname)+":"+str(port.port))

    # Now get all HTTPS services
    searchstring= 'service == "https%"'
    #print("querying filter: ", searchstring)
    search_result = hive_api.search(prj_id, search_string=searchstring)
    #print("got some results: ", len(search_result))
    for host in search_result:
        #print (host.id)
        for port in host.ports:
            print ("https://"+str(host.ip)+":"+str(port.port))
            for hostname in host.names:
                # skip wildcard hostnames
                if "*." in hostname.hostname:
                    continue
                print ("https://"+str(hostname.hostname)+":"+str(port.port))

get_target_list_4_web()