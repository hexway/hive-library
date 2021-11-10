#!/usr/bin/python3
from ipaddress import IPv4Address
from urllib.parse import urlparse
from hive_library.rest import HiveRestApi
from typing import Optional, List
import os
from marshmallow.fields import UUID
import argparse
import yaml
import requests
import socket
from hive_library import HiveLibrary
from hive_library.enum import RecordTypes
import logging
import traceback

###############################################
# Params handling here. You can use it for new importers or tols
'''
help_desc = '''

'''

parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-s', '--server-url', help='Hive server URL')
parser.add_argument('-u', '--user', help='Hive username')
parser.add_argument('-p', '--password', help='Hive password')
parser.add_argument('-P', '--project', help='Project UUID')
parser.add_argument('-f', '--file', help='Input file')

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
'''


###########################################
#set creds here for debug purposes only

username: str = "user@domain.tld"
password: str = "p@ssw0rd"
server: str = "http://hive.url.tld"
prj_id = "11111111-2222-4fd9-5555-666666666666"
###########################################


newtag="400 Plain bla bla bla"

# Connect to Hive and store provided creds to config at ~/.hive/config.yaml
hive_api: HiveRestApi = HiveRestApi(username=username, password=password, server=server)

cookie = hive_api._session.cookies._cookies[urlparse(server).hostname]['/']['SESSIONID'].value

def delete_node(node_id):
    url = server+"/api/project/"+prj_id+"/graph/nodes/"+str(node_id)
    x = requests.delete(url, cookies={"SESSIONID": cookie})
    print (x.text)

def delete_pics_by_record():
    #Delete pictures related to specified GoWitness records
    toolname = "GoWitness"
    searchstring = 'tag == "GoWitness"'
    rec_name = "Perception_hash"
    rec_value = "p:a323636367666666"  # 404
    # rec_name = "title"
    # rec_value = "400 The plain HTTP request was sent to HTTPS port"

    print ("querying filter: ", searchstring)
    search_result =hive_api.search(prj_id, search_string=searchstring)
    print ("got some results: ", len(search_result))
    for host in search_result:
        for current_port in host.ports:
            port = hive_api.get_port(prj_id, current_port.id)
            print ("Processing port:",port.port)
            for record in port.records:
                if record.import_type != toolname:
                    continue
                if record.value:
                    for record_value in record.value:
                        if record_value.name == rec_name:
                            print (record_value.value)
                            if record_value.value == rec_value:
                                print ("found a match:",record_value.name,record_value.value)
                                print ("got record at: ",port.ip, port.port)
                                #hive_api.create_tag(newtag, prj_id, port.id)
                                #print ("TAG: ", newtag, "added")
                                print ("record.name: ", record.name)
                                torem_scheme = urlparse(record.name).scheme
                                torem_name = urlparse(record.name).hostname
                                torem_port= str(urlparse(record.name).port)
                                file_2_remove = torem_scheme+"-"+torem_name+"-"+torem_port+".png"

                                print ("file to remove:", file_2_remove)
                                filename_found = 0
                                for filename in port.files:
                                    print ("\t",filename.name)
                                    if filename.name == file_2_remove:
                                        print ("[!]found  filename:", filename.name)
                                        print ("file ID 2 delete: ", filename.id )

                                        delete_node(filename.id)
                                        print ("======DELETED")

                                        filename_found =1
                                        continue
                                if filename_found == 0:
                                    print ("[!] file not found!")


def delete_similar_pics_for_port():
    toolname = "GoWitness"
    searchstring = 'tag == "GoWitness"'
    print ("querying filter: ", searchstring)
    search_result =hive_api.search(prj_id, search_string=searchstring)
    print ("got some results: ", len(search_result))
    for host in search_result:
        for current_port in host.ports:
            port = hive_api.get_port(prj_id, current_port.id)
            print ("Processing port:",port.port)
            perception_hashes = []
            for record in port.records:
                if record.import_type != toolname:
                    continue
                if record.value:

                    for record_value in record.value:
                        if record_value.name == "Perception_hash":
                            print ("checking value: ", record_value.value)
                            if record_value.value in perception_hashes:
                                print ("not uniq value, picture will be removed")

                                print("record.name: ", record.name)
                                torem_scheme = urlparse(record.name).scheme
                                torem_name = urlparse(record.name).hostname
                                torem_port = str(urlparse(record.name).port)
                                file_2_remove = torem_scheme + "-" + torem_name + "-" + torem_port + ".png"

                                print("file to remove:", file_2_remove)
                                filename_found = 0
                                for filename in port.files:
                                    print("\t", filename.name)
                                    if filename.name == file_2_remove:
                                        print("[!]found  filename:", filename.name)
                                        print("file ID 2 delete: ", filename.id)

                                        delete_node(filename.id)
                                        print("======DELETED")

                                        filename_found = 1
                                        continue
                                if filename_found == 0:
                                    print("[!] file not found!")



                            else:
                                perception_hashes.append(record_value.value)
                                print ("OK, value is uniq")


def fix_http_2_https_4_443():
    searchstring= 'port == 443 and service == "http"'
    print("querying filter: ", searchstring)
    search_result = hive_api.search(prj_id, search_string=searchstring)
    print("got some results: ", len(search_result))
    for host in search_result:
        new_host: HiveLibrary.Host = HiveLibrary.Host()
        new_host.ip = IPv4Address(host.ip)
        new_host.ports = [
            HiveLibrary.Host.Port(
                port=443,
                protocol="tcp",
                state="open",
                service=HiveLibrary.Host.Port.Service(
                    cpelist="",
                    name="https",
                    product="",
                    version="",
                ),
                records=[],
                # tags=[HiveLibrary.Tag(name="port_tag")],
            )
        ]
        task_id: Optional[UUID] = hive_api.create_host(project_id=prj_id, host=new_host)
        print ("fixed")

def delete_ips_by_filter():
    searchstring= 'ip == 10.0.0.0/8'
    print("querying filter: ", searchstring)
    search_result = hive_api.search(prj_id, search_string=searchstring)
    print("got some results: ", len(search_result))
    for host in search_result:
        print (host.id)
        delete_node(host.id)
        print ("DELETED!!")


def delete_noip_hostnames():
    searchstring= 'ip == ""'
    print("querying filter: ", searchstring)
    search_result = hive_api.search(prj_id, search_string=searchstring)
    print("got some results: ", len(search_result))
    for host in search_result:
        print (host.id)
        for hostname in host.names:
            print (hostname.hostname, hostname.id)
            delete_node(hostname.id)
            print ("DELETED!!")

def delete_wildcard_hostnames():
    searchstring= 'hostname == "*%"'
    print("querying filter: ", searchstring)
    search_result = hive_api.search(prj_id, search_string=searchstring)
    print("got some results: ", len(search_result))
    for host in search_result:
        print (host.id)
        for hostname in host.names:
            print (hostname.hostname, hostname.id)
            delete_node(hostname.id)
            print ("DELETED!!")


def delete_not_open_ports():
    searchstring= 'port.state != "open"'
    print("querying filter: ", searchstring)
    search_result = hive_api.search(prj_id, search_string=searchstring)
    print("got some results: ", len(search_result))
    for host in search_result:
        print (host.id)
        for hostname in host.names:
            print (hostname.hostname, hostname.id)
            print ("DELETED!!")

def delete_ip():
    searchstring= 'ip == 192.168.0.1'
    print("querying filter: ", searchstring)
    search_result = hive_api.search(prj_id, search_string=searchstring)
    print("got some results: ", len(search_result))
    for host in search_result:
        print (host.id)
        #for hostname in host.names:
        #    print (hostname.hostname, hostname.id)
        delete_node(host.id)
        print ("DELETED!!")


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



def add_lowercase_hostmanes():
    searchstring= 'hostname == "%%"'
    print("querying filter: ", searchstring)
    search_result = hive_api.search(prj_id, search_string=searchstring)
    print("got some results: ", len(search_result))
    for host in search_result:
        hostnames_list = []
        new_host: HiveLibrary.Host = HiveLibrary.Host()
        if host.ip is None:
            new_host.ip = None
        else:
            new_host.ip = IPv4Address(host.ip)
        print (host.ip)
        for hostname in host.names:
            delete_node(hostname.id)
            print (hostname.hostname, hostname.id)
            hostnames_list.append(
                HiveLibrary.Host.Name(
                    hostname=hostname.hostname.lower(),

                )
            )
        new_host.names = hostnames_list
        task_id: Optional[UUID] = hive_api.create_host(project_id=prj_id, host=new_host)



####################################


####################################

#delete_wildcard_hostnames()
#resolve_hostmanes_without_ip()
#delete_ips_by_filter()
#delete_similar_pics_for_port()
#add_lowercase_hostmanes()
