from hive_library import HiveLibrary
from hive_library.rest import HiveRestApi
from hive_library.enum import RecordTypes
from uuid import UUID
from ipaddress import IPv4Address
from time import sleep
from typing import Optional, List

# Connect to Hive server
username: Optional[str] = None
password: Optional[str] = None
server: Optional[str] = None
proxy: Optional[str] = None
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

# Create host
new_host: HiveLibrary.Host = HiveLibrary.Host()
new_host.ip = IPv4Address("192.168.0.1")
new_host.ports = [
    HiveLibrary.Host.Port(
        port=80,
        service=HiveLibrary.Host.Port.Service(
            cpelist="test service cpelist",
            name="http",
            product="Unit test",
            version="0.1",
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
        hostname="unit.test.com",
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

# Create note
new_note: Optional[HiveLibrary.Note] = hive_api.create_note(
    note_text="test note text", project_id=project.id, node_id=host.id
)
print(f"New note: \n{new_note}\n")

# Get list of notes
updated_hosts_list: Optional[List[HiveLibrary.Host]] = hive_api.get_hosts(
    project_id=project.id
)
print(f"Notes list: \n{updated_hosts_list[0].notes}\n")

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
imported_hosts: Optional[List[HiveLibrary.Host]] = hive_api.get_hosts(
    project_id=project.id
)
print(f"Imported hosts: \n{imported_hosts}\n")

# Delete project
deleted_project: Optional[HiveLibrary.Project] = hive_api.delete_project_by_name(
    project_name=new_project.name
)
print(f"Deleted project: \n{deleted_project}\n")
