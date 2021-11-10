#!/usr/bin/python3
import json
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

Import WhatWeb json results to Hive. 

1) run WhatWeb smth like:
whatweb -i ./targets.txt --log-json=whatweb_result.json 

2) Run import to Hive:
python3 ./whatweb2hive.py -P 11111111-2222-47ff-5555-66666666 -f whatweb_result.json

On a first run connection profile (server, username and password) will be stored at ~/.hive/config.yaml
'''


###############################################


parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-s', '--server-url', help='Hive server URL')
parser.add_argument('-u', '--user', help='Hive username')
parser.add_argument('-p', '--password', help='Hive password')
parser.add_argument('-P', '--project', help='Project UUID')
parser.add_argument('-f', '--file', help='Whatweb result json file')

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
#set creds here for debug purposes only
'''
username: str = "user@mail.tld"
password: str = "Passw0rd"
server: str = "http://your.hive.url.tld"
prj_id = "11111111-2222-4333-4444-555555555555"
###########################################
inputfile = "whatweb-result.json"
'''

# Connect to Hive and store provided creds to config at ~/.hive/config.yaml
hive_api: HiveRestApi = HiveRestApi(username=username, password=password, server=server)

with open(inputfile, encoding='utf-8') as json_file:
    whatwebdata = json.load(json_file)

for scan in whatwebdata:
    plugins = scan["plugins"]
    target = scan["target"]
    hostnames_list = []
    current_host = IPv4Address(plugins["IP"]['string'][0])
    print ("current ip:", current_host)


    if urlparse(target).port == None:
        print ("no port in URI so we use a scheme default")
        print (target)
        if urlparse(target).scheme == "https":
            current_port = 443
            print (urlparse(target).scheme+" -> 443")
        if urlparse(target).scheme == "http":
            current_port = 80
            print(urlparse(target).scheme + " -> 80")
    else:
        current_port = urlparse(target).port

    new_host: HiveLibrary.Host = HiveLibrary.Host()

    if plugins["IP"]["string"][0] != urlparse(target).hostname:

        hostnames_list.append(
        HiveLibrary.Host.Name(
            hostname=urlparse(target).hostname,
            # tags=[HiveLibrary.Tag(name="hostname_tag")],
        )
    )

    new_host.names = hostnames_list

    new_host.ip = current_host
    new_host.ports = [
        HiveLibrary.Host.Port(
            port=current_port,
            protocol="tcp",
            state="open",
            records=[
                HiveLibrary.Record(
                    name=target,
                    tool_name="WhatWeb",
                    record_type=RecordTypes.NESTED.value,
                    value=[
                    ],
                )
            ],
            # tags=[HiveLibrary.Tag(name="port_tag")],
        )
    ]

    print (plugins)
    for plugin in plugins:
        #print (plugin)
       # print (len(plugins[plugin]))
        values_list = []
       # print (plugin)
        for output in plugins[plugin]:
            #print ("\t", plugins[plugin][output])

            if isinstance(plugins[plugin][output], int):
                value = str (plugins[plugin][output])
            else:

                value = plugins[plugin][output][0]
                value = str(value)
                values_list.append(value)
        if len(values_list):
            if plugin == "UncommonHeaders":
                values_list = values_list[0].split(',')
            if plugin == "Strict-Transport-Security":
                values_list = values_list[0].split('; ')
            if len(values_list) >1:
                print (plugin)
                ##use LIST type of record

                new_record = HiveLibrary.Record(
                    name=plugin,
                    tool_name="WhatWeb",
                    record_type=RecordTypes.LIST.value,
                    value=values_list,
                )

                for prntval in values_list:
                    print ("-\t",prntval)
            else:
                ##use STRING type of record (1 value)

                new_record = HiveLibrary.Record(
                    name=plugin,
                    tool_name="WhatWeb",
                    record_type=RecordTypes.STRING.value,
                    value=values_list[0],
                )
                print (plugin, " : ", values_list[0])
        else:
            ##use STRING type of record (0 values)

            new_record = HiveLibrary.Record(
                name=plugin,
                tool_name="WhatWeb",
                record_type=RecordTypes.STRING.value,
                value="",
            )
            print(plugin)


        new_host.ports[0].records[0].value.append(new_record)

    print (new_host)
    task_id: Optional[UUID] = hive_api.create_host(project_id=prj_id, host=new_host)

    # Wait before import task is completed
#    for _ in range(10):
#        if hive_api.task_is_completed(project_id=prj_id, task_id=task_id):
#            break
#        else:
#            sleep(1)
    print(f"New host: \n{new_host}\n")

