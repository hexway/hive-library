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
import re

help_desc = '''
gowitness 2 hive

Uploads to Hive project:
    screensots
    Server Headers
    CN's from TLS certs
Also creates tag "GoWitness" for ports

python3 ./gowitness2hive.py -P 11111111-2222-47ff-5555-66666666 -f ./gowitness.sqlite3

On a first run connection profile (server, username and password) will be stored at ~/.hive/config.yaml
'''

parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-s', '--server-url', help='Hive server URL')
parser.add_argument('-u', '--user', help='Hive username')
parser.add_argument('-p', '--password', help='Hive password')
parser.add_argument('-P', '--project', help='get project list')
parser.add_argument('-f', '--file', help='gowitness.sqlite3 file')

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
    screenshots_dir = os.path.dirname(args.file)+"/screenshots/"
else:
    print("No gowitness.sqlite3 file specified! Use -f\n")
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


def is_ipv4(string):
    try:
        IPv4Address(string)
        return True
    except ValueError:
        return False

#open gowitness db file
con = sqlite3.connect(inputfile)
url_cur = con.cursor()
for url_row in url_cur.execute('select * from "urls"'):
    url_id = url_row[0]
    url = url_row[4]
    title = url_row[10]
    filename = url_row [11]
    perception_hash = url_row [12]
    
    
    if url == "":
        continue
    if url is None:
        continue
    if filename is None:
        continue
    if filename is "":
        continue

    headers_cur =  con.cursor()
    headers_list=[]
    hostnames_list = []
    for headers_row in headers_cur.execute('select * from "headers" where url_id ='+str(url_id)):
        header_name = (headers_row[5])
        header_value = str(headers_row[6])
        headers_list.append(header_name + " : " + header_value)
        #print (header_name , header_value)

    tls_cur = con.cursor()
    for tls_row in tls_cur.execute('select * from "tls" where url_id =' + str(url_id)):
        tls_id = tls_row[0]

        tls_certificates_cur = con.cursor()
        for tls_certificates_row in tls_certificates_cur.execute('select * from "tls_certificates" where tls_id =' + str(tls_id)):
            tls_certificate_id = tls_certificates_row[0]
            #print (tls_certificate_id)
            if tls_certificate_id:
                tls_certificate_dns_names_cur = con.cursor()
                for tls_certificate_dns_names_row in tls_certificate_dns_names_cur.execute('select * from "tls_certificate_dns_names" where tls_certificate_id =' + str(tls_certificate_id)):
                    name = str(tls_certificate_dns_names_row[5])
                    print (name)
                    hostnames_list.append(
                        HiveLibrary.Host.Name(
                            hostname=name,
                            #tags=[HiveLibrary.Tag(name="hostname_tag")],
                        )

                    )


    print ("processing file: " + filename)
    hostnameRE = "http(|s):\/\/([\w\d\-\.]+)(:\d{1,5}|)"
    hostnameMatchObj = re.match(hostnameRE, url)
    https = hostnameMatchObj.group(1)
    hostnameOrIP = hostnameMatchObj.group(2)
    portNumber = hostnameMatchObj.group(3)

    if is_ipv4(hostnameOrIP):
        current_host = IPv4Address(hostnameOrIP)
        record_name = hostnameOrIP
    else:
        search_result = hive_api.search_by_hostname(project_id=prj_id, hostname=hostnameOrIP )
        current_host = IPv4Address(search_result[0].ip)
        record_name = hostnameOrIP

    if portNumber:
    	current_port = int(portNumber[1:]) # [1:] Delete colon (:) from port number
    else:
        if https:
            current_port = 443
        else:
            current_port = 80

    port_id = hive_api.get_port_id(project_id= prj_id, port= current_port, ip=current_host)
    if port_id is None:
        continue

    print (current_host, current_port, port_id)


    #### Add records to the right inline panel

    new_host: HiveLibrary.Host = HiveLibrary.Host()
    new_host.ip = current_host
    new_host.ports = [
        HiveLibrary.Host.Port(
            port=current_port,
            protocol="tcp",
            state="open",
            records=[
                HiveLibrary.Record(
                    name=url,
                    tool_name="GoWitness",
                    record_type=RecordTypes.NESTED.value,
                    value=[

                        HiveLibrary.Record(
                            name="Perception_hash",
                            tool_name="GoWitness",
                            record_type=RecordTypes.STRING.value,
                            value=perception_hash
                        ),
                    ],
                )
            ],
            #tags=[HiveLibrary.Tag(name="port_tag")],
        )
    ]
   # print ("==============")

    new_record = HiveLibrary.Record(
                            name="Server Headers",
                            tool_name="GoWitness",
                            record_type=RecordTypes.LIST.value,
                            value=headers_list,
                        )
    new_host.ports[0].records[0].value.append(new_record)

    if title != '':
        title_record = HiveLibrary.Record(
                                name="title",
                                tool_name="GoWitness",
                                record_type=RecordTypes.STRING.value,
                                value=title,
                            )
        new_host.ports[0].records[0].value.append(title_record)

    #print (new_host.ports[0].records[0])

    ###### add hostnames ftom tls certs
    new_host.names = hostnames_list

    #new_host.tags = [HiveLibrary.Tag(name="host_tag")]
    task_id: Optional[UUID] = hive_api.create_host(project_id=prj_id, host=new_host)

    # Wait before import task is completed
    for _ in range(10):
        if hive_api.task_is_completed(project_id=prj_id, task_id=task_id):
            break
        else:
            sleep(1)
   # print(f"New host: \n{new_host}\n")

###########
    #Create Tag:
    new_tag: Optional[HiveLibrary.Tag] = hive_api.create_tag(
        tag_name="GoWitness", project_id=prj_id, node_id=port_id)

    #Upload screenshot if it present
    if os.path.isfile(screenshots_dir+filename):

        f = open(screenshots_dir +filename, "rb")
        file_data= f.read()

        new_file: Optional[HiveLibrary.Tag] = hive_api.upload_file(file_name=filename, file_caption="Screenshot", file_content=file_data, node_id=port_id, project_id= prj_id)
