# Description
"""
Hive REST API console client
Author: HexWay
License: MIT
Copyright 2021, HexWay
"""

# Import
from hive_library import HiveLibrary
from hive_library.rest import HiveRestApi, AuthenticationError
from hive_library.enum import RecordTypes
from argparse import ArgumentParser
from time import sleep
from uuid import UUID
from ipaddress import IPv4Address
from typing import Optional, List
from datetime import datetime
from prettytable import PrettyTable

# Authorship information
__author__ = "HexWay"
__copyright__ = "Copyright 2021, HexWay"
__credits__ = [""]
__license__ = "MIT"
__version__ = "0.0.1b1"
__maintainer__ = "HexWay"
__email__ = "contact@hexway.io"
__status__ = "Development"


# Pretty print hosts
def pretty_print_hosts(hosts: List[HiveLibrary.Host]) -> None:
    keys: List[str] = [
        "Id",
        "IP",
        "Hostname",
        "Tags",
        "Port id",
        "Port",
        "Proto",
        "Service",
        "Product",
        "Port tags",
    ]
    table: PrettyTable = PrettyTable(keys)
    for host in hosts:
        for port in host.ports:
            table.add_row(
                [
                    host.id,
                    host.ip,
                    ", ".join(str(name.hostname) for name in host.names),
                    ", ".join(str(tag.name) for tag in host.tags),
                    port.id,
                    port.port,
                    port.protocol,
                    port.service.name,
                    port.service.product + " " + port.service.version,
                    ", ".join(str(tag.name) for tag in port.tags),
                ]
            )
    print(table)


# Pretty print projects
def pretty_print_projects(projects: List[HiveLibrary.Project]) -> None:
    keys: List[str] = ["Id", "Name", "Description", "Start Date", "End Date"]
    table: PrettyTable = PrettyTable(keys)
    for project in projects:
        table.add_row(
            [
                project.id,
                project.name,
                project.description,
                project.start_date,
                project.end_date,
            ]
        )
    print(table)


# Main function
def main() -> None:
    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description="Hive REST API console client")

    # Hive arguments
    parser.add_argument(
        "-S", "--server_url", type=str, help="set Hive server URL", default=None
    )
    parser.add_argument(
        "-U", "--username", type=str, help="set Hive username", default=None
    )
    parser.add_argument(
        "-P", "--password", type=str, help="set Hive password", default=None
    )
    parser.add_argument(
        "-I", "--project_id", type=UUID, help="set project UUID", default=None
    )

    # Create project
    parser.add_argument(
        "--create_project", action="store_true", help="create Hive project"
    )
    parser.add_argument(
        "--project_name", type=str, help="set created Hive project name", default=None
    )
    parser.add_argument(
        "--project_description",
        type=str,
        help="set created Hive project description",
        default=None,
    )
    parser.add_argument(
        "--project_group",
        type=UUID,
        help="set created Hive project group UUID",
        default=None,
    )
    parser.add_argument(
        "--project_start",
        type=str,
        help="set created Hive project start date, example: 2021-01-01 01:01:01",
        default=None,
    )
    parser.add_argument(
        "--project_end",
        type=str,
        help="set created Hive project end date, example: 2021-02-01 01:01:01",
        default=None,
    )

    # Create host
    parser.add_argument("--create_host", action="store_true", help="create Hive host")
    parser.add_argument(
        "--host_tag", type=str, help="set created Hive host tag", default=None
    )
    parser.add_argument(
        "--host_name", type=str, help="set created Hive host name", default=None
    )
    parser.add_argument(
        "--host_ip",
        type=IPv4Address,
        help="set created Hive host IP address",
        default=None,
    )
    parser.add_argument(
        "--host_record_name",
        type=str,
        help="set created Hive host record name",
        default=None,
    )
    parser.add_argument(
        "--host_record_tool",
        type=str,
        help="set created Hive host record tool name",
        default=None,
    )
    parser.add_argument(
        "--host_record_val",
        type=str,
        help="set created Hive host record value",
        default=None,
    )
    parser.add_argument(
        "--port",
        type=int,
        help="set port for created Hive host",
        default=None,
    )
    parser.add_argument(
        "--port_tag", type=str, help="set port tag for created Hive host", default=None
    )
    parser.add_argument(
        "--port_proto",
        type=str,
        help="set port protocol for created Hive host",
        default="tcp",
    )
    parser.add_argument(
        "--port_state",
        type=str,
        help="set port state for created Hive host",
        default="open",
    )
    parser.add_argument(
        "--port_service_cpelist",
        type=str,
        help="set service cpelist in port for created Hive host",
        default=None,
    )
    parser.add_argument(
        "--port_service_name",
        type=str,
        help="set service name in port for created Hive host",
        default=None,
    )
    parser.add_argument(
        "--port_service_product",
        type=str,
        help="set service product in port for created Hive host",
        default=None,
    )
    parser.add_argument(
        "--port_service_version",
        type=str,
        help="set service version in port for created Hive host",
        default=None,
    )
    parser.add_argument(
        "--port_record_name",
        type=str,
        help="set record name for port in created Hive host",
        default=None,
    )
    parser.add_argument(
        "--port_record_tool",
        type=str,
        help="set record tool name for port in created Hive host",
        default=None,
    )
    parser.add_argument(
        "--port_record_val",
        type=str,
        help="set record value for port in created Hive host",
        default=None,
    )

    # Get objects
    parser.add_argument(
        "--get_projects", action="store_true", help="get Hive projects list"
    )
    parser.add_argument(
        "--get_groups", action="store_true", help="get Hive groups list"
    )
    parser.add_argument(
        "--get_hosts", action="store_true", help="get Hive hosts list for project"
    )
    parser.add_argument(
        "--get_host", type=int, help="get Hive host by identifier", default=None
    )
    parser.add_argument(
        "--get_port", type=int, help="get Hive port by identifier", default=None
    )

    # Search
    parser.add_argument(
        "--search_ip",
        type=IPv4Address,
        help="Search hosts by IP address",
        default=None,
    )
    parser.add_argument(
        "--search_port",
        type=int,
        help="Search hosts by port",
        default=None,
    )
    parser.add_argument(
        "--search_tag",
        type=str,
        help="Search hosts by tag",
        default=None,
    )
    parser.add_argument(
        "--search_service",
        type=str,
        help="Search hosts by service",
        default=None,
    )

    # Delete
    parser.add_argument(
        "--delete_project", type=str, help="delete Hive project by name", default=None
    )

    # Proxy
    parser.add_argument("-p", "--proxy", type=str, help="Set proxy URL", default=None)
    args = parser.parse_args()
    # endregion

    # Init HiveRestApi
    try:
        hive_api: HiveRestApi = HiveRestApi(
            username=args.username,
            password=args.password,
            server=args.server_url,
            proxy=args.proxy,
            project_id=args.project_id,
        )
    except AuthenticationError as error:
        print(f"Authentication Error: {error}")
        exit(1)

    # Get projects
    if args.get_projects:
        projects: Optional[List[HiveLibrary.Project]] = hive_api.get_projects_list()
        if len(projects) == 0:
            print("Not found projects!")
        else:
            print("Projects:")
            pretty_print_projects(projects=projects)
        exit(0)

    # Get groups
    if args.get_groups:
        groups: Optional[List[HiveLibrary.Group]] = hive_api.get_groups()
        if groups is None:
            print("Not found groups!")
        else:
            keys: List[str] = ["Id", "Name", "Description", "Projects"]
            table: PrettyTable = PrettyTable(keys)
            for group in groups:
                table.add_row(
                    [
                        group.id,
                        group.name,
                        group.description,
                        ", ".join(str(project.name) for project in group.projects),
                    ]
                )
            print(f"Groups:\n{table}")
        exit(0)

    # Create project
    if args.create_project:
        new_project: HiveLibrary.Project = HiveLibrary.Project()
        if args.project_name is not None:
            new_project.name = args.project_name
        else:
            print(
                "Hive project name is not set! "
                "Please set Hive project name argument: --project_name"
            )
            exit(4)
        if args.project_description is not None:
            new_project.description = args.project_description
        if args.project_group is not None:
            new_project.group_id = args.project_group
        if args.project_start is not None:
            new_project.start_date = datetime.strptime(args.project_start, "%Y-%m-%d")
        if args.project_end is not None:
            new_project.end_date = datetime.strptime(args.project_end, "%Y-%m-%d")
        created_project: Optional[HiveLibrary.Project] = hive_api.create_project(
            project=new_project
        )
        if created_project is None:
            print(f"Failed to create new project:")
        else:
            print(f"Successfully created new project:")
        keys: List[str] = ["Id", "Name", "Description", "Start Date", "End Date"]
        table: PrettyTable = PrettyTable(keys)
        table.add_row(
            [
                new_project.id,
                new_project.name,
                new_project.description,
                new_project.start_date,
                new_project.end_date,
            ]
        )
        print(table)
        exit(0)

    # Check project id is not None
    config: HiveLibrary.Config = HiveLibrary.load_config()
    if args.project_id is None:
        project_id = config.project_id
    else:
        project_id = args.project_id

    if project_id is None:
        print(
            "Hive project id is not set! "
            "Please set Hive project id in config file or argument: --project_id"
        )
        exit(3)

    # Create host
    if args.create_host:
        new_host: HiveLibrary.Host = HiveLibrary.Host()
        if args.host_ip is not None:
            new_host.ip = args.host_ip
        if args.host_name is not None:
            new_host.names = [HiveLibrary.Host.Name(hostname=args.host_name)]
        if args.host_tag is not None:
            new_host.tags = [HiveLibrary.Tag(name=args.host_tag)]
        if (
            args.host_record_name is not None
            and args.host_record_tool is not None
            and args.host_record_val is not None
        ):
            new_host.records = [
                HiveLibrary.Record(
                    name=args.host_record_name,
                    tool_name=args.host_record_tool,
                    record_type=RecordTypes.STRING.value,
                    value=args.host_record_val,
                )
            ]
        if args.port is not None:
            new_host.ports = [
                HiveLibrary.Host.Port(
                    port=args.port, protocol=args.port_proto, state=args.port_state
                )
            ]
        if args.port_tag is not None:
            new_host.ports[0].tags = [HiveLibrary.Tag(name=args.port_tag)]
        if (
            args.port_record_name is not None
            and args.port_record_tool is not None
            and args.port_record_val is not None
        ):
            new_host.ports[0].records = [
                HiveLibrary.Record(
                    name=args.port_record_name,
                    tool_name=args.port_record_tool,
                    record_type=RecordTypes.STRING.value,
                    value=args.port_record_val,
                )
            ]
        new_host.ports[0].service = HiveLibrary.Host.Port.Service()
        if args.port_service_cpelist is not None:
            new_host.ports[0].service.cpelist = args.port_service_cpelist
        if args.port_service_name is not None:
            new_host.ports[0].service.name = args.port_service_name
        if args.port_service_product is not None:
            new_host.ports[0].service.product = args.port_service_product
        if args.port_service_version is not None:
            new_host.ports[0].service.version = args.port_service_version
        task_id: Optional[UUID] = hive_api.create_host(
            project_id=project_id, host=new_host
        )
        if task_id is None:
            print(f"Failed to create new host:")
        else:
            print("Creating new host ...")
            for _ in range(30):
                if hive_api.task_is_completed(project_id=project_id, task_id=task_id):
                    break
                else:
                    sleep(1)
            if hive_api.task_is_completed(project_id=project_id, task_id=task_id):
                print(f"Successfully created new host:")
            else:
                print(f"Failed to create new host:")
        keys: List[str] = [
            "IP",
            "Hostname",
            "Port",
            "Proto",
            "Service",
            "Product",
            "Tags",
        ]
        table: PrettyTable = PrettyTable(keys)
        table.add_row(
            [
                new_host.ip,
                ", ".join(str(name.hostname) for name in new_host.names),
                new_host.ports[0].port,
                new_host.ports[0].protocol,
                new_host.ports[0].service.name,
                new_host.ports[0].service.product
                + " "
                + new_host.ports[0].service.version,
                ", ".join(str(tag.name) for tag in new_host.tags),
            ]
        )
        print(table)

    # Get hosts
    if args.get_hosts:
        hosts: Optional[List[HiveLibrary.Host]] = hive_api.get_hosts(
            project_id=project_id
        )
        if hosts is None or len(hosts) == 0:
            print(f"Not found hosts in project: {project_id}")
        else:
            print(f"Hosts in project: {project_id}")
            pretty_print_hosts(hosts=hosts)

    # Get host by id
    if args.get_host is not None:
        host: Optional[HiveLibrary.Host] = hive_api.get_host(
            project_id=project_id, host_id=int(args.get_host)
        )
        if host is None:
            print(f"Not found host with id: {args.get_host} in project: {project_id}")
        else:
            print(f"Host id: {args.get_host} in project: {project_id}")
            keys: List[str] = [
                "Id",
                "IP",
                "Hostname",
                "Tags",
                "Record id",
                "Record tool",
                "Record name",
                "Record value",
            ]
            table: PrettyTable = PrettyTable(keys)
            for record in host.records:
                if isinstance(record.value, List) and isinstance(
                    record.value[0], HiveLibrary.Record
                ):
                    for child_record in record.value:
                        table.add_row(
                            [
                                host.id,
                                host.ip,
                                ", ".join(str(name.hostname) for name in host.names),
                                ", ".join(str(tag.name) for tag in host.tags),
                                child_record.id,
                                child_record.import_type,
                                child_record.name,
                                child_record.value,
                            ]
                        )
                else:
                    table.add_row(
                        [
                            host.id,
                            host.ip,
                            ", ".join(str(name.hostname) for name in host.names),
                            ", ".join(str(tag.name) for tag in host.tags),
                            record.id,
                            record.import_type,
                            record.name,
                            record.value,
                        ]
                    )
            print(table)

    # Search by IP address
    if args.search_ip is not None:
        hosts: Optional[List[HiveLibrary.Host]] = hive_api.search_by_ip(
            project_id=project_id, ip=args.search_ip
        )
        if hosts is None or len(hosts) == 0:
            print(
                f"Not found hosts in project: {project_id} with ip address: {args.search_ip}"
            )
        else:
            print(f"Hosts in project: {project_id} with ip address: {args.search_ip}")
            pretty_print_hosts(hosts=hosts)

    # Search by port
    if args.search_port is not None:
        hosts: Optional[List[HiveLibrary.Host]] = hive_api.search_by_port(
            project_id=project_id, port=args.search_port
        )
        if hosts is None or len(hosts) == 0:
            print(
                f"Not found hosts in project: {project_id} with port: {args.search_port}"
            )
        else:
            print(f"Hosts in project: {project_id} with port: {args.search_port}")
            pretty_print_hosts(hosts=hosts)

    # Search by tag
    if args.search_tag is not None:
        hosts: Optional[List[HiveLibrary.Host]] = hive_api.search_by_tag(
            project_id=project_id, tag=args.search_tag
        )
        if hosts is None or len(hosts) == 0:
            print(
                f"Not found hosts in project: {project_id} with tag: {args.search_tag}"
            )
        else:
            print(f"Hosts in project: {project_id} with tag: {args.search_tag}")
            pretty_print_hosts(hosts=hosts)

    # Search by service
    if args.search_service is not None:
        hosts: Optional[List[HiveLibrary.Host]] = hive_api.search_by_service(
            project_id=project_id, service=args.search_service
        )
        if hosts is None or len(hosts) == 0:
            print(
                f"Not found hosts in project: {project_id} with service: {args.search_service}"
            )
        else:
            print(f"Hosts in project: {project_id} with service: {args.search_service}")
            pretty_print_hosts(hosts=hosts)

    # Delete project
    if args.delete_project is not None:
        deleted_project: Optional[
            HiveLibrary.Project
        ] = hive_api.delete_project_by_name(project_name=args.delete_project)
        if deleted_project is None:
            print(f"Not found project with name: {args.delete_project}")
        else:
            print("Deleted project:")
            pretty_print_projects(projects=[deleted_project])


# Call Main function
if __name__ == "__main__":
    main()
