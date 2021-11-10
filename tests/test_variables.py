# Description
"""
test_msf_api.py: Unit tests for MSF REST API
Author: HexWay
License: MIT
Copyright 2021, HexWay
"""

# Import
from hive_library import HiveLibrary
from hive_library.enum import RecordTypes
from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Optional

# Authorship information
__author__ = "HexWay"
__copyright__ = "Copyright 2021, HexWay"
__credits__ = [""]
__license__ = "MIT"
__version__ = "0.0.1b7"
__maintainer__ = "HexWay"
__email__ = "contact@hexway.io"
__status__ = "Development"


@dataclass
class HiveVariables:
    server: str = "http://127.0.0.1:8080"
    username: Optional[str] = None
    password: Optional[str] = None
    cookie: Optional[str] = None
    proxy: Optional[str] = "http://127.0.0.1:8888"

    project: HiveLibrary.Project = HiveLibrary.Project(
        name="test_project",
        description="Unit test project",
    )

    task: HiveLibrary.Task = HiveLibrary.Task(type="api_import")

    host: HiveLibrary.Host = HiveLibrary.Host(
        ip=IPv4Address("192.168.1.1"),
        records=[
            HiveLibrary.Record(
                name="unit test string host record",
                tool_name="unit_test_tool_name",
                record_type=RecordTypes.STRING.value,
                value="unit test string host record value",
            )
        ],
        names=[
            HiveLibrary.Host.Name(
                hostname="unit.test.com",
                records=[
                    HiveLibrary.Record(
                        name="unit test list hostname record",
                        tool_name="unit_test_tool_name",
                        record_type=RecordTypes.LIST.value,
                        value=[
                            "unit test list hostname record value 1",
                            "unit test list hostname record value 2",
                        ],
                    )
                ],
                tags=[HiveLibrary.Tag(name="hostname_tag")],
            )
        ],
        ports=[
            HiveLibrary.Host.Port(
                port=12345,
                service=HiveLibrary.Host.Port.Service(
                    cpelist="unit test service cpelist",
                    name="http",
                    product="Unit test",
                    version="0.1",
                ),
                protocol="tcp",
                state="open",
                records=[
                    HiveLibrary.Record(
                        name="unit test nested port record",
                        tool_name="unit_test_tool_name",
                        record_type=RecordTypes.NESTED.value,
                        value=[
                            HiveLibrary.Record(
                                name="unit test string port record 1",
                                tool_name="unit_test_tool_name",
                                record_type=RecordTypes.STRING.value,
                                value="unit test string port record 1 value",
                            ),
                            HiveLibrary.Record(
                                name="unit test string port record 2",
                                tool_name="unit_test_tool_name",
                                record_type=RecordTypes.STRING.value,
                                value="unit test string port record 2 value",
                            ),
                        ],
                    )
                ],
                tags=[HiveLibrary.Tag(name="port_tag")],
            )
        ],
        tags=[HiveLibrary.Tag(name="host_tag")],
    )

    note: HiveLibrary.Note = HiveLibrary.Note(text="unit test note text")

    tag: HiveLibrary.Tag = HiveLibrary.Tag(name="unit_test_tag_name")

    file_content: bytes = b"unit test file content"

    file: HiveLibrary.File = HiveLibrary.File(
        name="unit_test_file.txt",
        control_sum="sha256:747153e0f6b14eb609fd7cb6921fa871b08f26fec6e042075a2ab30a1af4d295",
        mime_type="text/plain",
        caption="Unit test file",
    )

    credential: HiveLibrary.Credential = HiveLibrary.Credential(
        type="password",
        login="unit_test_username",
        value="unit_test_password",
        description="unit test credential",
        tags=[HiveLibrary.Tag(name="credential_tag")],
    )

    snapshot: HiveLibrary.Snapshot = HiveLibrary.Snapshot(
        name="unit_test_snapshot_name",
        description="unit_test_snapshot_description",
    )
