Hive library
===================

## Description

This is a python library for working with Hive REST API.

That library allows you work with Hive REST API objects such as:

 - [Projects](#projects)
 - [Hosts](#hosts)
 - [Notes](#notes)
 - [Files](#files)
 - [Search](#search)
 - [Import hosts](#import)


## Python versions

 - Python 3.6
 - Python 3.7
 - Python 3.8
 - Python 3.9
 - Python 3.10

## Dependencies

 - [requests](https://pypi.org/project/requests/)
 - [urllib3](https://pypi.org/project/urllib3/)
 - [dataclasses](https://pypi.org/project/dataclasses/)
 - [marshmallow](https://pypi.org/project/marshmallow/)
 - [PyYAML](https://pypi.org/project/PyYAML/)

## Installing

Hive library can be installed with [pip](https://pypi.org/project/hive/):
```shell
pip3 install hive-library
```

Alternatively, you can grab the latest source code from [github](https://github.com/hexway/hive-library.git):
```shell
git clone https://github.com/hexway/hive-library.git
cd hive-library
python3 setup.py install
```

## Projects

```python
from hive_library import HiveLibrary
from hive_library.rest import HiveRestApi
from typing import Optional, List

# Connect to Hive server
username: str = "root@ro.ot"
password: str = "root12345"
server: str = "http://127.0.0.1:8080"
hive_api: HiveRestApi = HiveRestApi(username=username, password=password, server=server)

# Create project
new_project: Optional[HiveLibrary.Project] = hive_api.create_project(
    HiveLibrary.Project(name="test_project", description="test project")
)
print(f"New project: \n{new_project}\n")

# Get list of projects
projects_list: Optional[List[HiveLibrary.Project]] = hive_api.get_projects_list()
print(f"Projects list: \n{projects_list}\n")
project: HiveLibrary.Project = projects_list[0]

# Delete project
deleted_project: Optional[HiveLibrary.Project] = hive_api.delete_project_by_name(
    project_name=new_project.name
)
print(f"Deleted project: \n{deleted_project}\n")
```

## Hosts

```python
from hive_library import HiveLibrary
from hive_library.rest import HiveRestApi
from hive_library.enum import RecordTypes
from uuid import UUID
from ipaddress import IPv4Address
from time import sleep
from typing import Optional, List

# Connect to Hive server
username: str = "root@ro.ot"
password: str = "root12345"
server: str = "http://127.0.0.1:8080"
hive_api: HiveRestApi = HiveRestApi(username=username, password=password, server=server)

# Get list of projects
projects_list: Optional[List[HiveLibrary.Project]] = hive_api.get_projects_list()
print(f"Projects list: \n{projects_list}\n")
project: HiveLibrary.Project = projects_list[0]

# Create host
new_host: HiveLibrary.Host = HiveLibrary.Host()
new_host.ip = IPv4Address("192.168.0.1")
new_host.ports = [
    HiveLibrary.Host.Port(
        port=80,
        service=HiveLibrary.Host.Port.Service(
            cpelist="test service cpelist",
            name="http",
            product="Nginx",
            version="0.1337",
        ),
        protocol="tcp",
        state="open",
        records=[
            HiveLibrary.Record(
                name="test string port record",
                tool_name="test_tool_name",
                record_type=RecordTypes.NESTED.value,
                value=[
                    HiveLibrary.Record(
                        name="test nested port record 1",
                        tool_name="test_tool_name",
                        record_type=RecordTypes.STRING.value,
                        value="test nested port record 1 value",
                    ),
                    HiveLibrary.Record(
                        name="test nested port record 2",
                        tool_name="test_tool_name",
                        record_type=RecordTypes.STRING.value,
                        value="test nested port record 2 value",
                    ),
                ],
            )
        ],
        tags=[HiveLibrary.Tag(name="port_tag")],
    )
]
new_host.names = [
    HiveLibrary.Host.Name(
        hostname="evil.test.com",
        records=[
            HiveLibrary.Record(
                name="test list hostname record",
                tool_name="test_tool_name",
                record_type=RecordTypes.LIST.value,
                value=[
                    "test list hostname record value 1",
                    "test list hostname record value 2",
                ],
            )
        ],
        tags=[HiveLibrary.Tag(name="hostname_tag")],
    )
]
new_host.records = [
    HiveLibrary.Record(
        name="test nested host record",
        tool_name="test_tool_name",
        record_type=RecordTypes.STRING.value,
        value="test nested host record value",
    )
]
new_host.tags = [HiveLibrary.Tag(name="host_tag")]
task_id: Optional[UUID] = hive_api.create_host(project_id=project.id, host=new_host)

# Wait before import task is completed
for _ in range(10):
    if hive_api.task_is_completed(project_id=project.id, task_id=task_id):
        break
    else:
        sleep(1)
print(f"New host: \n{new_host}\n")

# Get list of hosts
hosts_list: Optional[List[HiveLibrary.Host]] = hive_api.get_hosts(project_id=project.id)
print(f"Hosts list: \n{hosts_list}\n")
host: HiveLibrary.Host = hosts_list[0]
```

## Notes

```python
from hive_library import HiveLibrary
from hive_library.rest import HiveRestApi
from typing import Optional, List

# Connect to Hive server
username: str = "root@ro.ot"
password: str = "root12345"
server: str = "http://127.0.0.1:8080"
hive_api: HiveRestApi = HiveRestApi(username=username, password=password, server=server)

# Get list of projects
projects_list: Optional[List[HiveLibrary.Project]] = hive_api.get_projects_list()
print(f"Projects list: \n{projects_list}\n")
project: HiveLibrary.Project = projects_list[0]

# Get list of hosts
hosts_list: Optional[List[HiveLibrary.Host]] = hive_api.get_hosts(project_id=project.id)
print(f"Hosts list: \n{hosts_list}\n")
host: HiveLibrary.Host = hosts_list[0]

# Create note
new_note: Optional[HiveLibrary.Note] = hive_api.create_note(
    note_text="test note text", project_id=project.id, node_id=host.id
)
print(f"New note: \n{new_note}\n")

# Get list of notes
updated_hosts_list: Optional[List[HiveLibrary.Host]] = hive_api.get_hosts(project_id=project.id)
print(f"Notes list: \n{updated_hosts_list[0].notes}\n")
```

## Files

```python
from hive_library import HiveLibrary
from HiveLibrary.rest import HiveRestApi
from typing import Optional, List

# Connect to Hive server
username: str = "root@ro.ot"
password: str = "root12345"
server: str = "http://127.0.0.1:8080"
hive_api: HiveRestApi = HiveRestApi(username=username, password=password, server=server)

# Get list of projects
projects_list: Optional[List[HiveLibrary.Project]] = hive_api.get_projects_list()
print(f"Projects list: \n{projects_list}\n")
project: HiveLibrary.Project = projects_list[0]

# Get list of hosts
hosts_list: Optional[List[HiveLibrary.Host]] = hive_api.get_hosts(project_id=project.id)
print(f"Hosts list: \n{hosts_list}\n")
host: HiveLibrary.Host = hosts_list[0]

# Create file
new_file: Optional[HiveLibrary.File] = hive_api.upload_file(
    file_name="test_file.txt",
    file_content=b"test file content",
    project_id=project.id,
    node_id=host.id,
)
print(f"New file: \n{new_file}\n")

# Get list of files
updated_hosts_list: Optional[List[HiveLibrary.Host]] = hive_api.get_hosts(
    project_id=project.id
)
print(f"Files list: \n{updated_hosts_list[0].files}\n")
```

```shell
Projects list: 
[HiveLibrary.Project(permission='ADMIN', group_id=UUID('2f1ba30c-af32-41a6-9c52-0a3a74397faa'), id=UUID('1c5be957-a2aa-4b52-9625-92faba22cdbe'), description='test project', name='test_project', create_date=datetime.datetime(2021, 5, 28, 17, 13, 34, 14052), is_archived=False, start_date=datetime.datetime(2021, 5, 28, 0, 0), end_date=datetime.datetime(2021, 6, 4, 0, 0), archive_date=None, hawser_id=None, scope=None, slug='test_project', full_slug='/default/test_project', users=None)]

Hosts list: 
[HiveLibrary.Host(checkmarks=[], files=[], id=81, uuid=UUID('b2e5e99a-8843-4465-bc12-5d4d10201425'), notes=None, ip=IPv4Address('192.168.0.1'), records=[], names=[HiveLibrary.Host.Name(checkmarks=[], files=[], id=85, ips=[], uuid=UUID('44c5720d-ccfa-431b-8770-e02de991a362'), notes=None, hostname='unit.test.com', records=[], tags=[HiveLibrary.Tag(id=88, uuid=None, name='hostname_tag', parent_id=None, base_node_id=None, labels=[], parent_labels=[])])], ports=[HiveLibrary.Host.Port(checkmarks=[], files=[], id=92, uuid=UUID('ae8e73c0-23c4-4e1e-8c59-2faf3d776ecd'), notes=None, port=80, service=HiveLibrary.Host.Port.Service(name='http', product='Unit test', version='0.1', cpelist='test service cpelist'), protocol='tcp', state='open', records=[], tags=[HiveLibrary.Tag(id=94, uuid=UUID('6170fb4a-9ed0-4308-aff7-f7b273cbc067'), name='port_tag', parent_id=None, base_node_id=None, labels=[], parent_labels=[])])], tags=[HiveLibrary.Tag(id=90, uuid=None, name='host_tag', parent_id=None, base_node_id=None, labels=[], parent_labels=[])])]

New file: 
HiveLibrary.File(base_node_id=None, caption=None, id=101, type=None, uuid=UUID('09e5c269-6741-4132-a7f5-391063720be0'), post_time=datetime.datetime(2021, 5, 28, 17, 13, 35, 357708), create_time=None, user_uuid=UUID('d491cf11-eb05-40f6-a915-d38bb22269f3'), creator_uuid=None, control_sum='sha256:60f5237ed4049f0382661ef009d2bc42e48c3ceb3edb6600f7024e7ab3b838f3', name='test_file.txt', size=17, mime_type='text/plain', node_id=None, parent_id=81, labels=['File'], parent_labels=['Ip'])

Files list: 
[HiveLibrary.File(base_node_id=None, caption=None, id=101, type=None, uuid=UUID('09e5c269-6741-4132-a7f5-391063720be0'), post_time=datetime.datetime(2021, 5, 28, 17, 13, 35, 357708), create_time=None, user_uuid=UUID('d491cf11-eb05-40f6-a915-d38bb22269f3'), creator_uuid=None, control_sum='sha256:60f5237ed4049f0382661ef009d2bc42e48c3ceb3edb6600f7024e7ab3b838f3', name='test_file.txt', size=17, mime_type='text/plain', node_id=None, parent_id=None, labels=[], parent_labels=[])]
```

## Search

```python
from hive_library import HiveLibrary
from HiveLibrary.rest import HiveRestApi
from ipaddress import IPv4Address
from typing import Optional, List

# Connect to Hive server
username: str = "root@ro.ot"
password: str = "root12345"
server: str = "http://127.0.0.1:8080"
hive_api: HiveRestApi = HiveRestApi(username=username, password=password, server=server)

# Get list of projects
projects_list: Optional[List[HiveLibrary.Project]] = hive_api.get_projects_list()
print(f"Projects list: \n{projects_list}\n")
project: HiveLibrary.Project = projects_list[0]

# Search variables
search_ip: IPv4Address = IPv4Address("192.168.0.1")
search_port: int = 80
search_hostname: str = "unit.test.com"
search_tag: str = "host_tag"
search_service: str = "http"

# Search by IP
search_hosts: Optional[List[HiveLibrary.Host]] = hive_api.search_by_ip(
    project_id=project.id, ip=search_ip
)
print(f"Search by IP ({search_ip}) hosts: \n{search_hosts}\n")

# Search by Port
search_hosts: Optional[List[HiveLibrary.Host]] = hive_api.search_by_port(
    project_id=project.id, port=search_port
)
print(f"Search by Port ({search_port}) hosts: \n{search_hosts}\n")

# Search by IP and Port
search_hosts: Optional[List[HiveLibrary.Host]] = hive_api.search_by_ip_and_port(
    project_id=project.id, ip=search_ip, port=search_port
)
print(f"Search by IP and Port ({search_ip}, {search_port}) hosts: \n{search_hosts}\n")

# Search by Hostname
search_hosts: Optional[List[HiveLibrary.Host]] = hive_api.search_by_hostname(
    project_id=project.id, hostname=search_hostname
)
print(f"Search by Hostname ({search_hostname}) hosts: \n{search_hosts}\n")

# Search by Tag
search_hosts: Optional[List[HiveLibrary.Host]] = hive_api.search_by_tag(
    project_id=project.id, tag=search_tag
)
print(f"Search by Tag ({search_tag}) hosts: \n{search_hosts}\n")

# Search by Service
search_hosts: Optional[List[HiveLibrary.Host]] = hive_api.search_by_service(
    project_id=project.id, service=search_service
)
print(f"Search by Service ({search_service}) hosts: \n{search_hosts}\n")
```

## Import

```python
from hive_library import HiveLibrary
from hive_library.rest import HiveRestApi
from uuid import UUID
from time import sleep
from typing import Optional, List

# Connect to Hive server
username: str = "root@ro.ot"
password: str = "root12345"
server: str = "http://127.0.0.1:8080"
hive_api: HiveRestApi = HiveRestApi(username=username, password=password, server=server)

# Get list of projects
projects_list: Optional[List[HiveLibrary.Project]] = hive_api.get_projects_list()
print(f"Projects list: \n{projects_list}\n")
project: HiveLibrary.Project = projects_list[0]

# Import from nmap xml
task_id: Optional[UUID] = hive_api.import_from_file(
    file_location="tests/nmap_test.xml", import_type="nmap", project_id=project.id
)

# Wait before import task is completed
for _ in range(10):
    if hive_api.task_is_completed(project_id=project.id, task_id=task_id):
        break
    else:
        sleep(1)

# Get imported hosts
imported_hosts: Optional[List[HiveLibrary.Host]] = hive_api.get_hosts(project_id=project.id)
print(f"Imported hosts: \n{imported_hosts}\n")
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/local/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.91 scan initiated Tue Apr 20 17:14:28 2021 as: nmap -A -Pn -&#45;open -oX tests/nmap_test.xml -v 192.168.1.1 -->
<nmaprun scanner="nmap" args="nmap -A -Pn -&#45;open -oX tests/nmap_test.xml -v 192.168.1.1" start="1618928068" startstr="Tue Apr 20 17:14:28 2021" version="7.91" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="1000" services="1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"/>
<verbose level="1"/>
<debugging level="0"/>
<host starttime="1618928068" endtime="1618928150"><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<hostnames>
<hostname name="unit.test.com" type="PTR"/>
</hostnames>
<ports><extraports state="filtered" count="997">
<extrareasons reason="no-responses" count="997"/>
</extraports>
<port protocol="tcp" portid="12345"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="Unit test" method="probed" conf="10"/><script id="http-methods" output="&#xa;  Supported Methods: GET HEAD POST OPTIONS"><table key="Supported Methods">
<elem>GET</elem>
<elem>HEAD</elem>
<elem>POST</elem>
<elem>OPTIONS</elem>
</table>
</script><script id="http-title" output="Site doesn&apos;t have a title (text/html)."></script></port>
</ports>
<times srtt="1584" rttvar="510" to="100000"/>
</host>
<runstats><finished time="1618928150" timestr="Tue Apr 20 17:15:50 2021" summary="Nmap done at Tue Apr 20 17:15:50 2021; 1 IP address (1 host up) scanned in 82.90 seconds" elapsed="82.90" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
```

