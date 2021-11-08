# Description
"""
test_hive_api.py: Unit tests for Hive REST API
Author: HexWay
License: MIT
Copyright 2021, HexWay
"""

# Import
from unittest import TestCase
from tests.test_variables import HiveVariables
from hive_library import HiveLibrary
from hive_library.rest import HiveRestApi
from hive_library.enum import RowTypes
from typing import Optional, List
from time import sleep
from uuid import UUID
from ipaddress import IPv4Address

# Authorship information
__author__ = "HexWay"
__copyright__ = "Copyright 2021, HexWay"
__credits__ = [""]
__license__ = "MIT"
__version__ = "0.0.1b6"
__maintainer__ = "HexWay"
__email__ = "contact@hexway.io"
__status__ = "Development"

# Global variables
variables: HiveVariables = HiveVariables()
hive_api: HiveRestApi = HiveRestApi(
    username=variables.username,
    password=variables.password,
    cookie=variables.cookie,
    server=variables.server,
    proxy=variables.proxy,
    debug=True,
)


# Class MsfRestApiTest
class HiveRestApiTest(TestCase):

    # Auth
    def test01_check_auth(self):
        hive_api._session.cookies.clear()
        del hive_api._session.headers["Cookie"]
        config: HiveLibrary.Config = HiveLibrary.load_config()
        variables.username = config.username
        variables.password = config.password
        user: Optional[HiveLibrary.User] = hive_api._password_auth(
            username=variables.username, password=variables.password
        )
        self.assertIsInstance(user, HiveLibrary.User)
        self.assertEqual(user.name, variables.username)
        cookie = hive_api._get_cookie()
        self.assertTrue(hive_api._check_cookie(cookie=cookie))

    # Work with projects
    def test02_create_project(self):
        hive_api.delete_project_by_name(project_name=variables.project.name)
        groups: Optional[List[HiveLibrary.Group]] = hive_api.get_groups()
        self.assertIsInstance(groups, List)
        group = groups[0]
        self.assertIsInstance(group, HiveLibrary.Group)
        self.assertIsInstance(group.id, UUID)
        variables.project.group_id = group.id
        new_project: Optional[HiveLibrary.Project] = hive_api.create_project(
            variables.project
        )
        self.assertIsInstance(new_project, HiveLibrary.Project)
        self.assertEqual(new_project.name, variables.project.name)
        self.assertEqual(
            new_project.description,
            variables.project.description,
        )
        self.assertEqual(new_project.users[0].name, variables.username)
        variables.project = new_project

    def test03_list_projects(self):
        projects_list = hive_api.get_projects_list()
        project_exist: bool = False
        self.assertIsInstance(projects_list, List)
        self.assertGreater(len(projects_list), 0)
        for project in projects_list:
            self.assertIsInstance(project, HiveLibrary.Project)
            if (
                project.name == variables.project.name
                and project.description == variables.project.description
            ):
                variables.project.id = project.id
                project_exist = True
                break
        self.assertTrue(project_exist)

    def test04_get_project_id_by_name(self):
        project_id = hive_api.get_project_id_by_name(
            project_name=variables.project.name
        )
        self.assertIsNotNone(project_id)
        self.assertEqual(project_id, variables.project.id)

    # Add data in project
    def test11_create_host(self):
        hosts: List[HiveLibrary.Host] = [variables.host]
        task_id: Optional[UUID] = hive_api.create_hosts(
            project_id=variables.project.id, hosts=hosts
        )
        self.assertIsNotNone(task_id)
        for _ in range(30):
            task: Optional[HiveLibrary.Task] = hive_api.get_task(
                project_id=variables.project.id, task_id=task_id
            )
            self.assertIsInstance(task, HiveLibrary.Task)
            self.assertEqual(task.project_id, variables.project.id)
            self.assertEqual(task.id, task_id)
            self.assertEqual(task.type, variables.task.type)
            if task.state == "SUCCESS":
                variables.task.id = task.id
                variables.task.state = task.state
                break
            sleep(1)
        self.assertIsNotNone(variables.task.id)

    def test12_task_is_completed(self):
        task_is_completed = hive_api.task_is_completed(
            project_id=variables.project.id, task_id=variables.task.id
        )
        self.assertTrue(task_is_completed)
        self.assertEqual("SUCCESS", variables.task.state)

    def test13_create_credential(self):
        ip_id = hive_api.get_ip_id(
            project_id=variables.project.id, ip=variables.host.ip
        )
        self.assertIsNotNone(ip_id)
        self.assertIsInstance(ip_id, int)
        variables.credential.asset_ids = [ip_id]
        credential: Optional[HiveLibrary.Credential] = hive_api.create_credential(
            project_id=variables.project.id, credential=variables.credential
        )
        self.assertIsNotNone(credential.id)
        self.assertIsNotNone(credential.uuid)
        self.assertEqual(credential.assets[0].asset, variables.host.ip)
        self.assertEqual(credential.assets[0].label, "Ip")
        self.assertEqual(credential.login, variables.credential.login)
        self.assertEqual(credential.type, variables.credential.type)
        self.assertEqual(credential.value, variables.credential.value)
        self.assertEqual(credential.description, variables.credential.description)
        self.assertIsNotNone(credential.tags[0].id)
        self.assertEqual(credential.tags[0].parent_id, credential.id)
        self.assertEqual(credential.tags[0].name, variables.credential.tags[0].name)
        variables.credential.id = credential.id
        variables.credential.uuid = credential.uuid
        variables.credential.tags = credential.tags

    # Get data in project
    def test21_get_ips(self):
        ip_labels = hive_api.get_ip_labels_for_project(project_id=variables.project.id)
        self.assertIsInstance(ip_labels, List)
        self.assertGreater(len(ip_labels), 0)
        ip_label = ip_labels[0]
        self.assertIsInstance(ip_label, HiveLibrary.Label)
        self.assertEqual(ip_label.count, 1)
        self.assertEqual(ip_label.label, variables.host.ip)

    def test22_get_ports(self):
        port_labels = hive_api.get_port_labels_for_project(
            project_id=variables.project.id
        )
        self.assertIsInstance(port_labels, List)
        self.assertGreater(len(port_labels), 0)
        port_label = port_labels[0]
        self.assertIsInstance(port_label, HiveLibrary.Label)
        self.assertEqual(port_label.count, 1)
        self.assertEqual(port_label.label, variables.host.ports[0].port)

    def test23_get_host(self):
        hosts = hive_api.get_hosts(project_id=variables.project.id)
        self.assertIsInstance(hosts, List)
        self.assertGreater(len(hosts), 0)

        host = hosts[0]
        self.assertIsInstance(host, HiveLibrary.Host)

        self.assertEqual(host.ip, variables.host.ip)
        variables.host.id = host.id
        variables.host.uuid = host.uuid

        self.assertEqual(host.names[0].hostname, variables.host.names[0].hostname)
        self.assertEqual(
            host.names[0].tags[0].name, variables.host.names[0].tags[0].name
        )

        variables.host.names[0].id = host.names[0].id
        variables.host.names[0].uuid = host.names[0].uuid

        self.assertEqual(host.ports[0].port, variables.host.ports[0].port)
        self.assertEqual(host.ports[0].protocol, variables.host.ports[0].protocol)
        self.assertEqual(host.ports[0].state, variables.host.ports[0].state)

        variables.host.ports[0].id = host.ports[0].id
        variables.host.ports[0].uuid = host.ports[0].uuid

        self.assertEqual(
            host.ports[0].service.cpelist, variables.host.ports[0].service.cpelist
        )
        self.assertEqual(
            host.ports[0].service.name, variables.host.ports[0].service.name
        )
        self.assertEqual(
            host.ports[0].service.product, variables.host.ports[0].service.product
        )
        self.assertEqual(
            host.ports[0].service.version, variables.host.ports[0].service.version
        )

    def test24_get_ip_id(self):
        ip_id = hive_api.get_ip_id(
            project_id=variables.project.id, ip=variables.host.ip
        )
        self.assertIsNotNone(ip_id)
        self.assertIsInstance(ip_id, int)
        self.assertEqual(variables.host.id, ip_id)

    def test25_get_port_id(self):
        port_id = hive_api.get_port_id(
            project_id=variables.project.id,
            ip=variables.host.ip,
            port=variables.host.ports[0].port,
        )
        self.assertIsNotNone(port_id)
        self.assertIsInstance(port_id, int)
        self.assertEqual(variables.host.ports[0].id, port_id)

    def test26_get_records(self):
        # Check host node
        host_node = hive_api.get_host(
            project_id=variables.project.id, host_id=variables.host.id
        )
        self.assertIsInstance(host_node, HiveLibrary.Host)
        self.assertEqual(host_node.names[0].hostname, variables.host.names[0].hostname)
        self.assertEqual(host_node.ip, variables.host.ip)
        self.assertEqual(host_node.id, variables.host.id)
        self.assertEqual(host_node.uuid, variables.host.uuid)
        self.assertEqual(host_node.ports[0].id, variables.host.ports[0].id)
        self.assertEqual(host_node.ports[0].port, variables.host.ports[0].port)
        self.assertEqual(host_node.ports[0].protocol, variables.host.ports[0].protocol)
        self.assertEqual(host_node.ports[0].state, variables.host.ports[0].state)
        self.assertEqual(host_node.records[0].name, variables.host.records[0].name)
        self.assertEqual(host_node.records[0].value, variables.host.records[0].value)
        self.assertEqual(host_node.sources[0].filename, "api_upload")

        # Check hostname node
        hostname_node = hive_api.get_hostname(
            project_id=variables.project.id, hostname_id=variables.host.names[0].id
        )
        self.assertIsInstance(hostname_node, HiveLibrary.Host.Name)
        self.assertEqual(hostname_node.ips[0].id, variables.host.id)
        self.assertEqual(hostname_node.ips[0].ip, variables.host.ip)
        self.assertEqual(hostname_node.id, variables.host.names[0].id)
        self.assertEqual(hostname_node.uuid, variables.host.names[0].uuid)
        self.assertEqual(hostname_node.hostname, variables.host.names[0].hostname)
        self.assertEqual(
            hostname_node.records[0].name, variables.host.names[0].records[0].name
        )
        self.assertEqual(
            hostname_node.records[0].value, variables.host.names[0].records[0].value
        )
        self.assertEqual(hostname_node.sources[0].filename, "api_upload")

        # Check Port node
        port_node = hive_api.get_port(
            project_id=variables.project.id, port_id=variables.host.ports[0].id
        )
        self.assertIsInstance(port_node, HiveLibrary.Host.Port)
        self.assertEqual(port_node.ip, variables.host.ip)
        self.assertEqual(port_node.id, variables.host.ports[0].id)
        self.assertEqual(port_node.uuid, variables.host.ports[0].uuid)
        self.assertEqual(port_node.port, variables.host.ports[0].port)
        self.assertEqual(port_node.protocol, variables.host.ports[0].protocol)
        self.assertEqual(port_node.state, variables.host.ports[0].state)
        self.assertEqual(port_node.service.name, variables.host.ports[0].service.name)
        self.assertEqual(
            port_node.service.product, variables.host.ports[0].service.product
        )
        self.assertEqual(
            port_node.records[0].name, variables.host.ports[0].records[0].name
        )
        self.assertIn(
            port_node.records[0].value[0].name,
            [
                variables.host.ports[0].records[0].value[0].name,
                variables.host.ports[0].records[0].value[1].name,
            ],
        )
        self.assertIn(
            port_node.records[0].value[0].value,
            [
                variables.host.ports[0].records[0].value[0].value,
                variables.host.ports[0].records[0].value[1].value,
            ],
        )
        self.assertIn(
            port_node.records[0].value[1].name,
            [
                variables.host.ports[0].records[0].value[0].name,
                variables.host.ports[0].records[0].value[1].name,
            ],
        )
        self.assertIn(
            port_node.records[0].value[1].value,
            [
                variables.host.ports[0].records[0].value[0].value,
                variables.host.ports[0].records[0].value[1].value,
            ],
        )
        self.assertEqual(port_node.sources[0].filename, "api_upload")

    def test27_get_credentials(self):
        credentials = hive_api.get_credentials(project_id=variables.project.id)
        self.assertIsInstance(credentials, List)
        self.assertEqual(len(credentials), 1)
        credential = credentials[0]
        self.assertEqual(credential.id, variables.credential.id)
        self.assertEqual(credential.uuid, variables.credential.uuid)
        self.assertEqual(credential.assets[0].asset, variables.host.ip)
        self.assertEqual(credential.assets[0].label, "Ip")
        self.assertEqual(credential.login, variables.credential.login)
        self.assertEqual(credential.type, variables.credential.type)
        self.assertEqual(credential.value, variables.credential.value)
        self.assertEqual(credential.description, variables.credential.description)
        self.assertEqual(credential.tags[0].id, variables.credential.tags[0].id)
        self.assertEqual(credential.tags[0].name, variables.credential.tags[0].name)

    # Create objects
    def test31_create_note(self):
        note = hive_api.create_note(
            note_text=variables.note.text,
            project_id=variables.project.id,
            node_id=variables.host.id,
        )
        self.assertIsInstance(note, HiveLibrary.Note)
        self.assertEqual(note.parent_id, variables.host.id)
        self.assertEqual(note.text, variables.note.text)
        variables.note.id = note.id

        hosts = hive_api.get_hosts(project_id=variables.project.id)
        self.assertIsInstance(hosts, List)
        self.assertGreater(len(hosts), 0)
        host = hosts[0]
        self.assertIsInstance(host, HiveLibrary.Host)
        notes = host.notes
        self.assertIsInstance(notes, List)
        self.assertGreater(len(notes), 0)
        note = notes[0]
        self.assertIsInstance(note, HiveLibrary.Note)
        self.assertEqual(note.text, variables.note.text)
        self.assertEqual(note.id, variables.note.id)

    def test32_create_tag(self):
        tag = hive_api.create_tag(
            tag_name=variables.tag.name,
            project_id=variables.project.id,
            node_id=variables.host.id,
        )
        self.assertIsInstance(tag, HiveLibrary.Tag)
        self.assertEqual(tag.parent_id, variables.host.id)
        self.assertEqual(tag.name, variables.tag.name)
        variables.tag.id = tag.id

        hosts = hive_api.get_hosts(project_id=variables.project.id)
        self.assertIsInstance(hosts, List)
        self.assertGreater(len(hosts), 0)
        host = hosts[0]
        self.assertIsInstance(host, HiveLibrary.Host)
        tags = host.tags
        self.assertIsInstance(tags, List)
        self.assertGreater(len(tags), 1)
        self.assertIn(tag.name, [t.name for t in tags])
        self.assertIn(tag.id, [t.id for t in tags])

    def test33_upload_file(self):
        file = hive_api.upload_file(
            file_name=variables.file.name,
            project_id=variables.project.id,
            node_id=variables.host.id,
            file_content=variables.file_content,
            file_caption=variables.file.caption,
        )
        self.assertIsInstance(file, HiveLibrary.File)
        self.assertEqual(file.name, variables.file.name)
        self.assertEqual(file.control_sum, variables.file.control_sum)
        self.assertEqual(file.mime_type, variables.file.mime_type)
        self.assertEqual(file.caption, variables.file.caption)
        variables.file.uuid = file.uuid
        variables.file.id = file.id

        hosts = hive_api.get_hosts(project_id=variables.project.id)
        self.assertIsInstance(hosts, List)
        self.assertGreater(len(hosts), 0)
        host = hosts[0]
        self.assertIsInstance(host, HiveLibrary.Host)
        files = host.files
        self.assertIsInstance(files, List)
        self.assertGreater(len(files), 0)
        file = files[0]
        self.assertIsInstance(file, HiveLibrary.File)
        self.assertEqual(file.name, variables.file.name)
        self.assertEqual(file.control_sum, variables.file.control_sum)
        self.assertEqual(file.mime_type, variables.file.mime_type)
        self.assertEqual(file.caption, variables.file.caption)
        self.assertEqual(file.uuid, variables.file.uuid)
        self.assertEqual(file.id, variables.file.id)

        file_content = hive_api.get_file(
            project_id=variables.project.id, file_uuid=variables.file.uuid
        )
        self.assertEqual(file_content, variables.file_content)

    def test34_make_snapshot(self):
        snapshot = hive_api.make_snapshot(
            project_id=variables.project.id,
            name=variables.snapshot.name,
            description=variables.snapshot.description,
        )
        self.assertIsInstance(snapshot, HiveLibrary.Snapshot)
        self.assertEqual(snapshot.name, variables.snapshot.name)
        self.assertEqual(snapshot.description, variables.snapshot.description)

    # Search
    def test41_search_by_ip(self):
        # List
        hosts = hive_api.search_by_ip(
            project_id=variables.project.id,
            ip=[variables.host.ip, IPv4Address("255.255.255.255")],
        )
        self.assertIsInstance(hosts, List)
        self.assertGreater(len(hosts), 0)

        host = hosts[0]
        self.assertEqual(host.id, variables.host.id)
        self.assertEqual(host.uuid, variables.host.uuid)
        self.assertEqual(host.ports[0].id, variables.host.ports[0].id)
        self.assertEqual(host.ports[0].uuid, variables.host.ports[0].uuid)

        # String
        hosts = hive_api.search_by_ip(
            project_id=variables.project.id, ip=variables.host.ip
        )
        self.assertIsInstance(hosts, List)
        self.assertGreater(len(hosts), 0)

        host = hosts[0]
        self.assertEqual(host.id, variables.host.id)
        self.assertEqual(host.uuid, variables.host.uuid)
        self.assertEqual(host.ports[0].id, variables.host.ports[0].id)
        self.assertEqual(host.ports[0].uuid, variables.host.ports[0].uuid)

        # Bad
        hosts = hive_api.search_by_ip(
            project_id=variables.project.id, ip=[IPv4Address("255.255.255.255")]
        )
        self.assertIsInstance(hosts, List)
        self.assertEqual(len(hosts), 0)

    def test42_search_by_port(self):
        # List
        hosts = hive_api.search_by_port(
            project_id=variables.project.id,
            port=[variables.host.ports[0].port, 65534],
        )
        self.assertIsInstance(hosts, List)
        self.assertGreater(len(hosts), 0)

        host = hosts[0]
        self.assertEqual(host.id, variables.host.id)
        self.assertEqual(host.uuid, variables.host.uuid)
        self.assertEqual(host.ports[0].id, variables.host.ports[0].id)
        self.assertEqual(host.ports[0].uuid, variables.host.ports[0].uuid)

        # String
        hosts = hive_api.search_by_port(
            project_id=variables.project.id, port=variables.host.ports[0].port
        )
        self.assertIsInstance(hosts, List)
        self.assertGreater(len(hosts), 0)

        host = hosts[0]
        self.assertEqual(host.id, variables.host.id)
        self.assertEqual(host.uuid, variables.host.uuid)
        self.assertEqual(host.ports[0].id, variables.host.ports[0].id)
        self.assertEqual(host.ports[0].uuid, variables.host.ports[0].uuid)

        # Bad
        hosts = hive_api.search_by_port(project_id=variables.project.id, port=[65534])
        self.assertIsInstance(hosts, List)
        self.assertEqual(len(hosts), 0)

    def test43_search_by_ip_and_port(self):
        # Normal
        hosts = hive_api.search_by_ip_and_port(
            project_id=variables.project.id,
            ip=variables.host.ip,
            port=variables.host.ports[0].port,
        )
        self.assertIsInstance(hosts, List)
        self.assertGreater(len(hosts), 0)

        host = hosts[0]
        self.assertEqual(host.id, variables.host.id)
        self.assertEqual(host.uuid, variables.host.uuid)
        self.assertEqual(host.ports[0].id, variables.host.ports[0].id)
        self.assertEqual(host.ports[0].uuid, variables.host.ports[0].uuid)

        # Bad IP
        hosts = hive_api.search_by_ip_and_port(
            project_id=variables.project.id,
            ip=IPv4Address("255.255.255.255"),
            port=variables.host.ports[0].port,
        )
        self.assertIsInstance(hosts, List)
        self.assertEqual(len(hosts), 0)

        # Bad port
        hosts = hive_api.search_by_ip_and_port(
            project_id=variables.project.id,
            ip=variables.host.ip,
            port=65534,
        )
        self.assertIsInstance(hosts, List)
        self.assertEqual(len(hosts), 0)

        # Bad all
        hosts = hive_api.search_by_ip_and_port(
            project_id=variables.project.id,
            ip=IPv4Address("255.255.255.255"),
            port=65534,
        )
        self.assertIsInstance(hosts, List)
        self.assertEqual(len(hosts), 0)

    def test44_search_by_tag(self):
        # List
        hosts = hive_api.search_by_tag(
            project_id=variables.project.id,
            tag=[variables.host.tags[0].name, "not-real-tag"],
        )
        self.assertIsInstance(hosts, List)
        self.assertGreater(len(hosts), 0)

        host = hosts[0]
        self.assertEqual(host.id, variables.host.id)
        self.assertEqual(host.uuid, variables.host.uuid)
        self.assertEqual(host.ports[0].id, variables.host.ports[0].id)
        self.assertEqual(host.ports[0].uuid, variables.host.ports[0].uuid)

        # String
        hosts = hive_api.search_by_tag(
            project_id=variables.project.id, tag=variables.host.tags[0].name
        )
        self.assertIsInstance(hosts, List)
        self.assertGreater(len(hosts), 0)

        host = hosts[0]
        self.assertEqual(host.id, variables.host.id)
        self.assertEqual(host.uuid, variables.host.uuid)
        self.assertEqual(host.ports[0].id, variables.host.ports[0].id)
        self.assertEqual(host.ports[0].uuid, variables.host.ports[0].uuid)

        # Bad
        hosts = hive_api.search_by_tag(
            project_id=variables.project.id, tag=["not-real-tag"]
        )
        self.assertIsInstance(hosts, List)
        self.assertEqual(len(hosts), 0)

    def test45_search_by_hostname(self):
        # List
        hosts = hive_api.search_by_hostname(
            project_id=variables.project.id,
            hostname=[variables.host.names[0].hostname, "not-real.hostname.com"],
        )
        self.assertIsInstance(hosts, List)
        self.assertGreater(len(hosts), 0)

        host = hosts[0]
        self.assertEqual(host.id, variables.host.id)
        self.assertEqual(host.uuid, variables.host.uuid)
        self.assertEqual(host.ports[0].id, variables.host.ports[0].id)
        self.assertEqual(host.ports[0].uuid, variables.host.ports[0].uuid)

        # String
        hosts = hive_api.search_by_hostname(
            project_id=variables.project.id, hostname=variables.host.names[0].hostname
        )
        self.assertIsInstance(hosts, List)
        self.assertGreater(len(hosts), 0)

        host = hosts[0]
        self.assertEqual(host.id, variables.host.id)
        self.assertEqual(host.uuid, variables.host.uuid)
        self.assertEqual(host.ports[0].id, variables.host.ports[0].id)
        self.assertEqual(host.ports[0].uuid, variables.host.ports[0].uuid)

        # Bad
        hosts = hive_api.search_by_hostname(
            project_id=variables.project.id, hostname=["not-real.hostname.com"]
        )
        self.assertIsInstance(hosts, List)
        self.assertEqual(len(hosts), 0)

    def test46_search_by_service(self):
        # List
        hosts = hive_api.search_by_service(
            project_id=variables.project.id,
            service=[variables.host.ports[0].service.name, "ssh"],
        )
        self.assertIsInstance(hosts, List)
        self.assertGreater(len(hosts), 0)

        host = hosts[0]
        self.assertEqual(host.id, variables.host.id)
        self.assertEqual(host.uuid, variables.host.uuid)
        self.assertEqual(host.ports[0].id, variables.host.ports[0].id)
        self.assertEqual(host.ports[0].uuid, variables.host.ports[0].uuid)

        # String
        hosts = hive_api.search_by_service(
            project_id=variables.project.id,
            service=variables.host.ports[0].service.name,
        )
        self.assertIsInstance(hosts, List)
        self.assertGreater(len(hosts), 0)

        host = hosts[0]
        self.assertEqual(host.id, variables.host.id)
        self.assertEqual(host.uuid, variables.host.uuid)
        self.assertEqual(host.ports[0].id, variables.host.ports[0].id)
        self.assertEqual(host.ports[0].uuid, variables.host.ports[0].uuid)

        # Bad
        hosts = hive_api.search_by_service(
            project_id=variables.project.id, service=["ssh"]
        )
        self.assertIsInstance(hosts, List)
        self.assertEqual(len(hosts), 0)

    # Delete methods
    def test51_delete_project(self):
        deleted_project = hive_api.delete_project_by_name(
            project_name=variables.project.name
        )
        self.assertIsInstance(deleted_project, HiveLibrary.Project)
        self.assertEqual(deleted_project.id, variables.project.id)
        self.assertEqual(deleted_project.name, variables.project.name)
        self.assertEqual(deleted_project.description, variables.project.description)

    # Import from nmap xml file
    def test52_import_from_nmap(self):
        hive_api.delete_project_by_name(project_name=variables.project.name)
        new_project = hive_api.create_project(variables.project)
        self.assertIsInstance(new_project, HiveLibrary.Project)
        self.assertEqual(new_project.name, variables.project.name)
        project_id = new_project.id

        task_id = hive_api.import_from_file(
            file_location="nmap_test.xml", import_type="nmap", project_id=project_id
        )
        self.assertIsInstance(task_id, UUID)

        for _ in range(10):
            if hive_api.task_is_completed(project_id=project_id, task_id=task_id):
                break
            else:
                sleep(1)

        hosts = hive_api.get_hosts(project_id=project_id)
        self.assertIsInstance(hosts, List)
        host = hosts[0]
        self.assertIsInstance(host, HiveLibrary.Host)
        self.assertEqual(host.ip, variables.host.ip)
        self.assertEqual(host.names[0].hostname, variables.host.names[0].hostname)
        self.assertEqual(host.ports[0].port, variables.host.ports[0].port)
        self.assertEqual(host.ports[0].protocol, variables.host.ports[0].protocol)
        self.assertEqual(host.ports[0].state, variables.host.ports[0].state)
        self.assertEqual(
            host.ports[0].service.name, variables.host.ports[0].service.name
        )
        self.assertEqual(
            host.ports[0].service.product, variables.host.ports[0].service.product
        )

        deleted_project = hive_api.delete_project_by_name(
            project_name=variables.project.name
        )
        self.assertIsInstance(deleted_project, HiveLibrary.Project)
        self.assertEqual(deleted_project.name, variables.project.name)

    # Import from metasploit xml file
    def test53_import_from_metasploit(self):
        hive_api.delete_project_by_name(project_name=variables.project.name)
        new_project = hive_api.create_project(variables.project)
        self.assertIsInstance(new_project, HiveLibrary.Project)
        self.assertEqual(new_project.name, variables.project.name)
        project_id = new_project.id

        task_id = hive_api.import_from_file(
            file_location="msf_test.xml",
            import_type="metasploit",
            project_id=project_id,
        )
        self.assertIsInstance(task_id, UUID)

        for _ in range(10):
            if hive_api.task_is_completed(project_id=project_id, task_id=task_id):
                break
            else:
                sleep(1)

        hosts = hive_api.get_hosts(project_id=project_id)
        self.assertIsInstance(hosts, List)
        host = hosts[0]
        self.assertIsInstance(host, HiveLibrary.Host)
        self.assertEqual(host.ip, variables.host.ip)
        self.assertEqual(host.names[0].hostname, variables.host.names[0].hostname)
        self.assertEqual(host.ports[0].port, variables.host.ports[0].port)
        self.assertEqual(host.ports[0].protocol, variables.host.ports[0].protocol)
        self.assertEqual(host.ports[0].state, variables.host.ports[0].state)
        self.assertEqual(
            host.ports[0].service.name, variables.host.ports[0].service.name
        )
        self.assertEqual(
            host.ports[0].service.product, variables.host.ports[0].service.product
        )

        host_id: int = host.id
        port_id: int = host.ports[0].id

        host_node = hive_api.get_host(project_id=project_id, host_id=host_id)
        found_msf_note_record: bool = False
        found_msf_host_record: bool = False
        for record in host_node.records:
            if record.name.startswith("Note"):
                for value in record.value:
                    if (
                        value.name == "Note data"
                        and value.value == "Unit test host comment"
                    ):
                        found_msf_note_record = True
                        break
            if record.name.startswith("Host"):
                for value in record.value:
                    if value.name == "Host IP address" and value.value == "192.168.1.1":
                        found_msf_host_record = True
                        break
        self.assertTrue(found_msf_note_record)
        self.assertTrue(found_msf_host_record)

        port_node = hive_api.get_port(project_id=project_id, port_id=port_id)
        found_msf_vuln_record: bool = False
        for record in port_node.records:
            if record.name.startswith("Vulnerability"):
                for value in record.value:
                    if (
                        value.name == "Vulnerability name"
                        and value.value == "Unit test vuln name"
                    ):
                        found_msf_vuln_record = True
                        break
        self.assertTrue(found_msf_vuln_record)

        deleted_project = hive_api.delete_project_by_name(
            project_name=variables.project.name
        )
        self.assertIsInstance(deleted_project, HiveLibrary.Project)
        self.assertEqual(deleted_project.name, variables.project.name)

    # Import from cobalt strike xml files
    def test54_import_from_cobalt_strike(self):
        hive_api.delete_project_by_name(project_name=variables.project.name)
        new_project = hive_api.create_project(variables.project)
        self.assertIsInstance(new_project, HiveLibrary.Project)
        self.assertEqual(new_project.name, variables.project.name)
        project_id = new_project.id

        tasks: List[UUID] = list()
        for file in [
            "cobaltstrike_targets.xml",
            "cobaltstrike_services.xml",
            "cobaltstrike_credentials.xml",
            "cobaltstrike_sessions.xml",
        ]:
            task_id = hive_api.import_from_file(
                file_location=file,
                import_type="cobaltstrike",
                project_id=project_id,
            )
            tasks.append(task_id)

        for task_id in tasks:
            for _ in range(10):
                if hive_api.task_is_completed(project_id=project_id, task_id=task_id):
                    break
                else:
                    sleep(1)

        hosts = hive_api.get_hosts(project_id=project_id)
        self.assertIsInstance(hosts, List)
        host = hosts[0]
        self.assertIsInstance(host, HiveLibrary.Host)
        self.assertEqual(host.ip, variables.host.ip)
        self.assertEqual(host.names[0].hostname, variables.host.names[0].hostname)
        self.assertEqual(host.ports[0].port, variables.host.ports[0].port)
        self.assertEqual(host.ports[0].protocol, variables.host.ports[0].protocol)
        self.assertEqual(host.ports[0].state, variables.host.ports[0].state)
        self.assertEqual(
            host.ports[0].service.product, variables.host.ports[0].service.product
        )

        host_id: int = host.id

        host_node = hive_api.get_host(project_id=project_id, host_id=host_id)
        found_cs_host_record: bool = False
        found_cs_cred_record: bool = False
        found_cs_sess_record: bool = False
        for record in host_node.records:
            if record.name == "Host information":
                for value in record.value:
                    if value.name == "Host OS name" and value.value == "linux":
                        found_cs_host_record = True
                        break
            if record.name == "Credentials":
                for value in record.value:
                    if value.name == "Credential: UnitTestUser":
                        found_cs_cred_record = True
                        break
            if record.name == "Sessions":
                for value in record.value:
                    if value.name == "Session: UnitTestUser (12345)":
                        found_cs_sess_record = True
                        break
        self.assertTrue(found_cs_host_record)
        self.assertTrue(found_cs_cred_record)
        self.assertTrue(found_cs_sess_record)

        deleted_project = hive_api.delete_project_by_name(
            project_name=variables.project.name
        )
        self.assertIsInstance(deleted_project, HiveLibrary.Project)
        self.assertEqual(deleted_project.name, variables.project.name)

    # Import from nuclei json file
    def test55_import_from_nuclei(self):
        hive_api.delete_project_by_name(project_name=variables.project.name)
        new_project = hive_api.create_project(variables.project)
        self.assertIsInstance(new_project, HiveLibrary.Project)
        self.assertEqual(new_project.name, variables.project.name)
        project_id = new_project.id

        task_id = hive_api.import_from_file(
            file_location="nuclei_test.json",
            import_type="nuclei",
            project_id=project_id,
            advanced_options=["autoTag", "importNucleiTags"],
        )
        self.assertIsInstance(task_id, UUID)

        for _ in range(10):
            if hive_api.task_is_completed(project_id=project_id, task_id=task_id):
                break
            else:
                sleep(1)

        hosts = hive_api.get_hosts(project_id=project_id)
        self.assertIsInstance(hosts, List)
        host = hosts[0]
        self.assertIsInstance(host, HiveLibrary.Host)
        self.assertEqual(host.ip, variables.host.ip)
        self.assertEqual(host.names[0].hostname, variables.host.names[0].hostname)
        self.assertEqual(host.ports[0].port, variables.host.ports[0].port)
        self.assertEqual(host.ports[0].protocol, variables.host.ports[0].protocol)
        self.assertEqual(host.ports[0].state, variables.host.ports[0].state)

        port_id: int = host.ports[0].id

        port_node = hive_api.get_host(project_id=project_id, host_id=port_id)
        found_nc_template_record: bool = False
        found_nc_severity_record: bool = False
        found_nc_matched_record: bool = False
        for record in port_node.records[0].value:
            if record.name == "Template ID" and record.value == "CVE-2018-15473":
                found_nc_template_record = True
            if record.name == "Severity" and record.value == "low":
                found_nc_severity_record = True
            if record.name == "Matched" and record.value == "unit.test.com:12345":
                found_nc_matched_record = True
        self.assertTrue(found_nc_template_record)
        self.assertTrue(found_nc_severity_record)
        self.assertTrue(found_nc_matched_record)

        deleted_project = hive_api.delete_project_by_name(
            project_name=variables.project.name
        )
        self.assertIsInstance(deleted_project, HiveLibrary.Project)
        self.assertEqual(deleted_project.name, variables.project.name)

    # Custom import
    def test56_custom_import(self):
        hive_api.delete_project_by_name(project_name=variables.project.name)
        new_project = hive_api.create_project(variables.project)
        self.assertIsInstance(new_project, HiveLibrary.Project)
        self.assertEqual(new_project.name, variables.project.name)
        project_id = new_project.id

        # Parse custom import
        rows = hive_api.parse_custom_import(
            project_id=project_id,
            data=f"{variables.host.names[0].hostname},{variables.host.ip}",
            columns=[RowTypes.HOSTNAME.value, RowTypes.IP.value],
            column_separator=",",
            row_separator="\n",
        )
        self.assertIsInstance(rows, List)
        self.assertIsInstance(rows[0], HiveLibrary.Row)
        row: HiveLibrary.Row = rows[0]
        self.assertEqual(row.ip, str(variables.host.ip))
        self.assertEqual(row.hostname, str(variables.host.names[0].hostname))

        # Upload custom import
        task = hive_api.upload_custom_import(
            project_id=project_id,
            rows=[
                HiveLibrary.Row(
                    ip=variables.host.ip, hostname=variables.host.names[0].hostname
                )
            ],
        )
        self.assertIsInstance(task, HiveLibrary.Task)
        self.assertEqual(task.type, "custom_import")
        self.assertEqual(task.project_id, project_id)

        hosts = hive_api.get_hosts(project_id=project_id)
        self.assertIsInstance(hosts, List)
        host = hosts[0]
        self.assertIsInstance(host, HiveLibrary.Host)
        self.assertEqual(host.ip, variables.host.ip)
        self.assertEqual(host.names[0].hostname, variables.host.names[0].hostname)

        hive_api.delete_project_by_name(project_name=variables.project.name)
        new_project = hive_api.create_project(variables.project)
        self.assertIsInstance(new_project, HiveLibrary.Project)
        self.assertEqual(new_project.name, variables.project.name)
        project_id = new_project.id

        # Custom import
        task = hive_api.custom_import(
            project_id=project_id,
            file_location="custom_import.txt",
            columns=[RowTypes.HOSTNAME.value, RowTypes.IP.value],
            column_separator=",",
            row_separator="\n",
        )
        self.assertIsInstance(task, HiveLibrary.Task)
        self.assertEqual(task.type, "custom_import")
        self.assertEqual(task.project_id, project_id)

        hosts = hive_api.get_hosts(project_id=project_id)
        self.assertIsInstance(hosts, List)
        host = hosts[0]
        self.assertIsInstance(host, HiveLibrary.Host)
        self.assertIn(str(host.ip), ["1.1.1.1", "2.2.2.2"])
        self.assertIn(str(host.names[0].hostname), ["test1.com", "test2.com"])

        hive_api.delete_project_by_name(project_name=variables.project.name)
