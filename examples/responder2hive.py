#!/usr/bin/python3
from ipaddress import IPv4Address
from time import sleep
from urllib.parse import urlparse
from hive_library.enum import RecordTypes
from hive_library import HiveLibrary
from hive_library.rest import HiveRestApi
from typing import Optional, List
import sqlite3
import os
from marshmallow.fields import UUID
import argparse
import yaml

from hive_library import HiveLibrary
from hive_library.enum import RecordTypes

help_desc = '''
Responder db 2 hive 

Uploads to Hive project loot from Responder.db:

python3 ./responder2hive.py -P 11111111-2222-47ff-5555-66666666 -f ./Responder.db

On a first run connection profile (server, username and password) will be stored at ~/.hive/config.yaml
'''

parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-s', '--server-url', help='Hive server URL')
parser.add_argument('-u', '--user', help='Hive username')
parser.add_argument('-p', '--password', help='Hive password')
parser.add_argument('-P', '--project', help='Project UUID')
parser.add_argument('-f', '--file', help='Responder.db file')

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
if args.file:
    inputfile = args.file
    
else:
    print("No Responder.db file specified! Use -f\n")
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
hive_api: HiveRestApi = HiveRestApi(username=username, password=password, server=server)
creds = hive_api.get_credentials(project_id=prj_id)

def is_cred_exist(login, value):
    for cred in creds:
        if cred.login == login and cred.value == value:
            print ("skipping already existing cred:", responder_user)
            return 1
    return 0

con = sqlite3.connect(inputfile)
responder_cur = con.cursor()
for cred_row in responder_cur.execute('select * from "responder"'):
    responder_timestamp = cred_row[0]
    responder_module = cred_row[1]
    responder_type = cred_row[2]
    responder_client = cred_row[3]
    responder_hostname = cred_row[4]
    responder_user = cred_row[5]
    responder_cleartext = cred_row[6]
    responder_hash = cred_row[7]
    responder_fullhash = cred_row[8]

    if not responder_cleartext:
        value= responder_fullhash
    else:
        value = responder_cleartext

    if is_cred_exist(responder_user, value):
        continue

    new_host: HiveLibrary.Host = HiveLibrary.Host()
    new_host.ip = IPv4Address(responder_client)
    task_id: Optional[UUID] = hive_api.create_host(project_id=prj_id, host=new_host)

    # Wait before import task is completed
    for _ in range(10):
        if hive_api.task_is_completed(project_id=prj_id, task_id=task_id):
            break
        else:
            sleep(1)
    #print(f"New host added: \n{new_host}\n")

    ip_id = hive_api.get_ip_id(project_id=prj_id, ip=IPv4Address(responder_client))
    #print (ip_id)

    credential: HiveLibrary.Credential = HiveLibrary.Credential(
        type=responder_type,
        login=responder_user,
        value=value,
        description=responder_module,
        tags=[HiveLibrary.Tag(name="Responder")],
        asset_ids= [ip_id]
    )
    print("cred:\t",responder_user,value)
    hive_api.create_credential(project_id=prj_id, credential=credential )

