# Description
"""
Hive dataclasses
Author: HexWay
License: MIT
Copyright 2021, HexWay
"""

# Import
from hive_library.enum import RecordTypes, PermissionTypes, TaskStates
from typing import List, Dict, Optional, Union
from uuid import UUID
from dataclasses import dataclass, field
from marshmallow import (
    fields,
    pre_load,
    post_load,
    pre_dump,
    post_dump,
    validate,
    EXCLUDE,
)
from marshmallow import Schema as MarshmallowSchema
from datetime import datetime
from ipaddress import ip_address, IPv4Address
from yaml import safe_load, safe_dump
from os import path
from os import makedirs
from pathlib import Path


# Authorship information
__author__ = "HexWay"
__copyright__ = "Copyright 2021, HexWay"
__credits__ = [""]
__license__ = "MIT"
__version__ = "0.0.1b1"
__maintainer__ = "HexWay"
__email__ = "contact@hexway.io"
__status__ = "Development"


PermissionTypes = PermissionTypes.list()
RecordTypes = RecordTypes.list()
TaskStates = TaskStates.list()


class HiveLibrary:
    @dataclass
    class Config:
        file: str = f"{str(Path.home())}/.hive/config.yaml"
        server: Optional[str] = None
        proxy: Optional[str] = None
        username: Optional[str] = None
        password: Optional[str] = None
        cookie: Optional[str] = None
        project_id: Optional[UUID] = None

        class Schema(MarshmallowSchema):
            server = fields.String(missing=None)
            proxy = fields.String(missing=None)
            username = fields.String(missing=None)
            password = fields.String(missing=None)
            cookie = fields.String(missing=None)
            project_id = fields.UUID(missing=None)

            @post_dump(pass_many=False)
            def clean_missing(self, data, many, **kwargs):
                clean_data = data.copy()
                for key in filter(lambda key: data[key] is None, data):
                    del clean_data[key]
                return clean_data

            @post_load
            def make_config(self, data, **kwargs):
                return HiveLibrary.Config(**data)

    @dataclass
    class User:
        create_date: Optional[datetime] = None
        email: Optional[str] = None
        id: Optional[UUID] = None
        is_admin: bool = False
        is_confirmed: bool = False
        last_confirmed: Optional[datetime] = None
        login: Optional[str] = None
        name: Optional[str] = None
        permission_type: Optional[str] = None
        user: Optional[Dict[str, str]] = None

        class Schema(MarshmallowSchema):
            permission_type = fields.String(
                validate=validate.OneOf(PermissionTypes),
                data_key="permissionType",
                missing=None,
            )
            user = fields.Dict(missing=None)
            create_date = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ",
                missing=None,
                data_key="userCreateDate",
            )
            email = fields.String(data_key="userEmail")
            id = fields.UUID(required=True, data_key="userId")
            is_admin = fields.Bool(default=False, data_key="userIsAdmin")
            is_confirmed = fields.Bool(default=False, data_key="userIsConfirmed")
            last_confirmed = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ",
                missing=None,
                data_key="userLastConfirmed",
            )
            login = fields.Str(missing=None, data_key="userLogin")
            name = fields.Str(missing=None, data_key="userName")

            @post_load
            def make_user(self, data, **kwargs):
                return HiveLibrary.User(**data)

    @dataclass
    class Group:
        def __str__(self):
            return self.name

        children: Optional[List["HiveLibrary.Group"]] = field(
            default_factory=lambda: []
        )
        create_date: Optional[datetime] = None
        description: Optional[str] = None
        full_slug: Optional[str] = None
        id: Optional[UUID] = None
        last_updated: Optional[datetime] = None
        name: Optional[str] = None
        parent_id: Optional[str] = None
        permission_type: Optional[str] = None
        projects: Optional[List["HiveLibrary.Project"]] = field(
            default_factory=lambda: []
        )
        slug: Optional[str] = None
        users: Optional[List["HiveLibrary.User"]] = field(default_factory=lambda: [])

        class Schema(MarshmallowSchema):
            permission_type = fields.String(
                validate=validate.OneOf(PermissionTypes),
                missing=None,
                data_key="permissionType",
            )
            parent_id = fields.UUID(allow_none=True, missing=None, data_key="parentId")
            id = fields.UUID(required=True)
            description = fields.String(missing=None)
            name = fields.String(required=True)
            create_date = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", required=True, data_key="createDate"
            )
            last_updated = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", required=True, data_key="lastUpdated"
            )
            slug = fields.String(missing=None)
            full_slug = fields.String(missing=None, data_key="fullSlug")
            projects = fields.Nested(lambda: HiveLibrary.Project.Schema, many=True)
            children = fields.Nested(lambda: HiveLibrary.Group.Schema, many=True)
            users = fields.Nested(lambda: HiveLibrary.User.Schema, many=True)

            @post_load
            def make_group(self, data, **kwargs):
                return HiveLibrary.Group(**data)

    @dataclass
    class Project:
        permission: Optional[str] = None
        group_id: Optional[UUID] = None
        id: Optional[UUID] = None
        description: Optional[str] = None
        name: Optional[str] = None
        create_date: Optional[datetime] = None
        is_archived: bool = False
        start_date: Optional[datetime] = None
        end_date: Optional[datetime] = None
        archive_date: Optional[datetime] = None
        hawser_id: Optional[UUID] = None
        scope: Optional[str] = None
        slug: Optional[str] = None
        full_slug: Optional[str] = None
        users: Optional[List["HiveLibrary.User"]] = field(default_factory=lambda: [])

        def __str__(self):
            return self.name

        class Schema(MarshmallowSchema):
            permission = fields.String(
                validate=validate.OneOf(PermissionTypes),
                load_only=True,
                missing=None,
                data_key="projectPermission",
                nullable=True,
            )
            group_id = fields.UUID(
                allow_none=True, missing=None, data_key="projectGroupId"
            )
            id = fields.UUID(load_only=True, required=True, data_key="projectId")
            description = fields.String(missing=None, data_key="projectDescription")
            name = fields.String(required=True, data_key="projectName")
            create_date = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ",
                required=True,
                load_only=True,
                data_key="projectCreateDate",
            )
            is_archived = fields.Boolean(load_only=True, data_key="projectIsArchived")
            start_date = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", data_key="projectStartDate"
            )
            end_date = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", data_key="projectEndDate"
            )
            archive_date = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ",
                load_only=True,
                missing=None,
                data_key="projectArchiveDate",
            )
            hawser_id = fields.UUID(
                load_only=True,
                allow_none=True,
                missing=None,
                data_key="projectConnectionId",
            )
            scope = fields.String(load_only=True, missing=None, data_key="projectScope")
            slug = fields.String(load_only=True, missing=None, data_key="projectSlug")
            full_slug = fields.String(
                load_only=True, missing=None, data_key="projectFullSlug"
            )
            users = fields.Nested(
                lambda: HiveLibrary.User.Schema,
                load_only=True,
                missing=None,
                many=True,
                data_key="projectUsers",
            )

            @post_dump(pass_many=False)
            def clean_missing(self, data, many, **kwargs):
                clean_data = data.copy()
                for key in filter(lambda key: data[key] is None, data):
                    del clean_data[key]
                return clean_data

            @post_load
            def make_project(self, data, **kwargs):
                return HiveLibrary.Project(**data)

    @dataclass
    class Task:
        id: Optional[UUID] = None
        type: Optional[str] = None
        user_id: Optional[UUID] = None
        project_id: Optional[UUID] = None
        data_source_id: Optional[int] = None
        file_id: Optional[int] = None
        file_uuid: Optional[UUID] = None
        file_name: Optional[str] = None
        file_node_id: Optional[int] = None
        timestamp: Optional[datetime] = None
        state: Optional[str] = None
        total: Optional[int] = None
        current: Optional[int] = None
        exc_message: Optional[str] = None
        exc_type: Optional[str] = None

        class Schema(MarshmallowSchema):
            id = fields.UUID(required=True, data_key="taskId")
            type = fields.String(required=True, data_key="taskType")
            user_id = fields.UUID(required=True, data_key="userId")
            project_id = fields.UUID(required=True, data_key="projectId")
            data_source_id = fields.Integer(missing=None, data_key="datasourceId")
            file_id = fields.Integer(missing=None, data_key="fileId")
            file_uuid = fields.UUID(missing=None, data_key="fileUuid")
            file_name = fields.String(missing=None, data_key="filename")
            file_node_id = fields.Integer(missing=None, data_key="filenodeId")
            timestamp = fields.DateTime("%Y-%m-%dT%H:%M:%S.%fZ", required=True)
            state = fields.String(
                validate=validate.OneOf(TaskStates),
                allow_none=False,
                required=True,
            )
            total = fields.Integer(required=False, default=None, missing=None)
            current = fields.Integer(required=False, default=None, missing=None)
            exc_message = fields.String(missing=None)
            exc_type = fields.String(missing=None)

            @post_load
            def make_task(self, data, **kwargs):
                return HiveLibrary.Task(**data)

    @dataclass
    class Label:
        count: Optional[int] = None
        label: Union[None, int, str, IPv4Address] = None

        class Schema(MarshmallowSchema):
            count = fields.Integer(default=None, allow_none=True)
            label = fields.Raw(default=None, allow_none=True)

            @post_load
            def make_label(self, data, **kwargs):
                try:
                    if isinstance(data["label"], str):
                        data["label"] = ip_address(data["label"])
                except ValueError:
                    pass
                return HiveLibrary.Label(**data)

    @dataclass
    class Tag:
        parent_id: Optional[int] = None
        id: Optional[int] = None
        name: Optional[str] = None

        class Schema(MarshmallowSchema):
            parent_id = fields.Integer(missing=None, default=None, data_key="parentId")
            id = fields.Integer(default=None, allow_none=True)
            name = fields.String(default=None, allow_none=True)

            class Meta:
                unknown = EXCLUDE

            @post_dump(pass_many=True)
            def parse_tags(self, data, many, **kwargs):
                if len(data) > 0:
                    tags: List[str] = list()
                    for tag in data:
                        tags.append(tag["name"])
                    return tags
                else:
                    return data

            @post_load
            def make_tag(self, data, **kwargs):
                return HiveLibrary.Tag(**data)

    @dataclass
    class Checkmark:
        id: Optional[int] = None
        uuid: Optional[UUID] = None
        type: Optional[str] = None
        create_time: Optional[datetime] = None
        creator_uuid: Optional[UUID] = None
        editor_uuid: Optional[UUID] = None
        description: Optional[str] = None
        done: bool = False
        synchronizable: bool = False
        name: Optional[str] = None
        order: Optional[int] = None
        children: Optional[List["HiveLibrary.Checkmark"]] = field(
            default_factory=lambda: []
        )

        class Schema(MarshmallowSchema):
            id = fields.Integer(
                load_only=True, missing=None, default=None, data_key="_id"
            )
            uuid = fields.UUID(default=None, allow_none=True)
            type = fields.String(
                load_only=True, missing=None, default=None, data_key="_type"
            )
            create_time = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ",
                load_only=True,
                data_key="createTime",
                missing=None,
            )
            creator_uuid = fields.UUID(
                load_only=True, missing=None, default=None, data_key="creatorUuid"
            )
            editor_uuid = fields.UUID(
                load_only=True, missing=None, default=None, data_key="editorUuid"
            )
            description = fields.String(default=None, allow_none=True)
            done = fields.Bool(default=False)
            synchronizable = fields.Bool(default=False)
            name = fields.String(default=None, allow_none=True)
            order = fields.Integer(
                load_only=True, missing=None, default=None, data_key="order"
            )
            children = fields.Nested(
                lambda: HiveLibrary.Checkmark.Schema,
                many=True,
                missing=[],
                default=[],
                allow_none=True,
                data_key="childcheckmark",
            )

            class Meta:
                unknown = EXCLUDE

            @pre_load(pass_many=False)
            def pre_make_checkmark(self, data, **kwargs):
                if "id" in data:
                    data["_id"] = data["id"]
                    del data["id"]
                return data

            @post_load
            def make_checkmark(self, data, **kwargs):
                return HiveLibrary.Checkmark(**data)

    @dataclass
    class Record:
        children: Optional[List["HiveLibrary.Record"]] = field(
            default_factory=lambda: []
        )
        create_time: Optional[datetime] = None
        creator_uuid: Optional[UUID] = None
        extra: Optional[str] = None
        id: Optional[int] = None
        uuid: Optional[UUID] = None
        import_type: Optional[str] = None
        name: Optional[str] = None
        tool_name: Optional[str] = None
        record_type: Optional[str] = None
        value: Union[
            None, int, str, List[Union[int, str, "HiveLibrary.Record"]]
        ] = field(default_factory=lambda: [])

        class Schema(MarshmallowSchema):
            children = fields.Nested(
                lambda: HiveLibrary.Record.Schema,
                load_only=True,
                many=True,
                missing=[],
                default=[],
            )
            create_time = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ",
                load_only=True,
                data_key="createTime",
                missing=None,
            )
            creator_uuid = fields.UUID(
                data_key="creatorUuid", load_only=True, missing=None
            )
            extra = fields.String(load_only=True, missing=None)
            id = fields.Integer(load_only=True, missing=None)
            uuid = fields.UUID(load_only=True, missing=None)
            import_type = fields.String(
                data_key="importType", load_only=True, missing=None
            )
            name = fields.String(missing=None)
            tool_name = fields.String(missing=None, default="nmap")
            record_type = fields.String(
                validate=validate.OneOf(RecordTypes),
            )
            value = fields.Raw(missing=None)

            @pre_dump(pass_many=True)
            def parse_records(self, data, many, **kwargs):
                if isinstance(data, List):
                    result_list: List[Dict] = list()
                    for record in data:
                        if isinstance(record, HiveLibrary.Record):
                            result: Dict = dict()
                            for key in ["name", "tool_name", "record_type"]:
                                result[key] = record.__dict__[key]
                            result["value"] = self.parse_records(
                                record.__dict__["value"], True
                            )
                            result_list.append(result)
                        else:
                            result_list.append(record)
                    return result_list
                else:
                    if isinstance(data, HiveLibrary.Record):
                        result: Dict = dict()
                        for key in ["name", "tool_name", "record_type"]:
                            result[key] = data.__dict__[key]
                        result["value"] = self.parse_records(
                            data.__dict__["value"], True
                        )
                        return result
                    else:
                        return data

            @pre_load(pass_many=False)
            def pre_make_record(self, data, **kwargs):
                for key in data:
                    if key == "recordType":
                        data["record_type"] = data["recordType"]
                        del data["recordType"]
                        break
                return data

            @post_load
            def make_record(self, data, **kwargs):
                if isinstance(data["value"], List):
                    new_values: List = list()
                    for value in data["value"]:
                        if isinstance(value, Dict):
                            new_values.append(self.make_record(value))
                        else:
                            new_values.append(value)
                    data["value"] = new_values
                if "children" in data:
                    if len(data["children"]) > 0 and data["value"] is None:
                        data["value"] = data["children"]
                return HiveLibrary.Record(**data)

    @dataclass
    class Source:
        id: Optional[int] = None
        uuid: Optional[UUID] = None
        comment: Optional[str] = None
        creator_uuid: Optional[UUID] = None
        filename: Optional[str] = None
        import_status: Optional[str] = None
        labels: Optional[List[str]] = field(default_factory=lambda: [])
        name: Optional[str] = None
        post_time: Optional[datetime] = None
        type: Optional[str] = None

        class Schema(MarshmallowSchema):
            id = fields.Integer(missing=None)
            uuid = fields.UUID(missing=None)
            comment = fields.String(missing=None)
            creator_uuid = fields.UUID(data_key="creatorUuid", missing=None)
            filename = fields.String(missing=None)
            import_status = fields.String(data_key="importStatus", missing=None)
            labels = fields.List(
                fields.String,
                many=True,
                missing=[],
                default=[],
                allow_none=True,
            )
            name = fields.String(missing=None)
            post_time = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", data_key="postTime", missing=None
            )
            type = fields.String(missing=None)

            @post_load
            def make_source(self, data, **kwargs):
                return HiveLibrary.Source(**data)

    @dataclass
    class IP:
        id: Optional[int] = None
        ip: Optional[IPv4Address] = None
        uuid: Optional[UUID] = None

        class Schema(MarshmallowSchema):
            id = fields.Integer(load_only=True, missing=None, default=None)
            ip = fields.IPv4(load_only=True, missing=None, default=None)
            uuid = fields.UUID(load_only=True, missing=None, default=None)

            class Meta:
                unknown = EXCLUDE

            @post_load
            def make_ip(self, data, **kwargs):
                return HiveLibrary.IP(**data)

    @dataclass
    class File:
        parent_id: Optional[int] = None
        id: Optional[int] = None
        uuid: Optional[UUID] = None
        create_time: Optional[datetime] = None
        creator_uuid: Optional[UUID] = None
        node_id: Optional[int] = None
        caption: Optional[str] = None
        control_sum: Optional[str] = None
        name: Optional[str] = None
        size: Optional[int] = None
        mime_type: Optional[str] = None

        class Schema(MarshmallowSchema):
            parent_id = fields.Integer(
                load_only=True, missing=None, default=None, data_key="parentId"
            )
            id = fields.Integer(load_only=True, missing=None, default=None)
            uuid = fields.UUID(missing=None, default=None)
            create_time = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ",
                load_only=True,
                data_key="createTime",
                missing=None,
            )
            creator_uuid = fields.UUID(
                load_only=True, missing=None, default=None, data_key="creatorUuid"
            )
            node_id = fields.Integer(missing=None, default=None, data_key="nodeId")
            caption = fields.String(missing=None, default=None)
            control_sum = fields.String(
                missing=None, default=None, data_key="controlSum"
            )
            name = fields.String(missing=None, default=None, data_key="filename")
            size = fields.Integer(missing=None, default=None, data_key="filesize")
            mime_type = fields.String(missing=None, default=None, data_key="mimetype")

            class Meta:
                unknown = EXCLUDE

            @pre_load(pass_many=False)
            def pre_make_file(self, data, **kwargs):
                if "mimeType" in data:
                    data["mimetype"] = data["mimeType"]
                    del data["mimeType"]
                return data

            @post_load
            def make_file(self, data, **kwargs):
                return HiveLibrary.File(**data)

    @dataclass
    class Note:

        def __str__(self):
            return self.text

        parent_id: Optional[int] = None
        id: Optional[int] = None
        uuid: Optional[UUID] = None
        create_time: Optional[datetime] = None
        creator_uuid: Optional[UUID] = None
        text: Optional[str] = None
        files: Optional[List["HiveLibrary.File"]] = field(default_factory=lambda: [])
        notes: Optional[List["HiveLibrary.Note"]] = field(default_factory=lambda: [])
        tags: Optional[List["HiveLibrary.Tag"]] = field(default_factory=lambda: [])

        class Schema(MarshmallowSchema):
            parent_id = fields.Integer(
                load_only=True, missing=None, default=None, data_key="parentId"
            )
            id = fields.Integer(load_only=True, missing=None, default=None)
            uuid = fields.UUID(load_only=True, missing=None, default=None)
            create_time = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ",
                load_only=True,
                data_key="createTime",
                missing=None,
            )
            creator_uuid = fields.UUID(
                load_only=True, missing=None, default=None, data_key="creatorUuid"
            )
            text = fields.String(missing=None, default=None)
            files = fields.Nested(
                lambda: HiveLibrary.File.Schema,
                load_only=True,
                many=True,
                missing=[],
                default=[],
                allow_none=True,
            )
            notes = fields.Nested(
                lambda: HiveLibrary.Note.Schema,
                load_only=True,
                many=True,
                missing=[],
                default=[],
                allow_none=True,
            )
            tags = fields.Nested(
                lambda: HiveLibrary.Tag.Schema,
                load_only=True,
                many=True,
                missing=[],
                default=[],
            )

            class Meta:
                unknown = EXCLUDE

            @post_load
            def make_note(self, data, **kwargs):
                return HiveLibrary.Note(**data)

    @dataclass
    class Host:
        checkmarks: Optional[List["HiveLibrary.Checkmark"]] = field(
            default_factory=lambda: []
        )
        files: Optional[List["HiveLibrary.File"]] = field(default_factory=lambda: [])
        id: Optional[int] = None
        uuid: Optional[UUID] = None
        notes: Optional[List["HiveLibrary.Note"]] = field(default_factory=lambda: [])
        ip: Optional[IPv4Address] = None
        ip_binary: Optional[str] = None
        records: Optional[List["HiveLibrary.Record"]] = field(
            default_factory=lambda: []
        )
        names: Optional[List["HiveLibrary.Host.Name"]] = field(
            default_factory=lambda: []
        )
        ports: Optional[List["HiveLibrary.Host.Port"]] = field(
            default_factory=lambda: []
        )
        sources: Optional[List["HiveLibrary.Source"]] = field(
            default_factory=lambda: []
        )
        tags: Optional[List["HiveLibrary.Tag"]] = field(default_factory=lambda: [])

        class Schema(MarshmallowSchema):
            checkmarks = fields.Nested(
                lambda: HiveLibrary.Checkmark.Schema,
                load_only=True,
                many=True,
                data_key="checkmarks",
                missing=[],
                default=[],
            )
            files = fields.Nested(
                lambda: HiveLibrary.File.Schema,
                many=True,
                data_key="files",
                missing=[],
                default=[],
                allow_none=True,
            )
            id = fields.Integer(
                load_only=True, missing=None, default=None, data_key="id"
            )
            uuid = fields.UUID(
                load_only=True, missing=None, default=None, data_key="uuid"
            )
            notes = fields.Nested(
                lambda: HiveLibrary.Note.Schema,
                load_only=True,
                many=True,
                data_key="notes",
                missing=[],
                default=[],
                allow_none=True,
            )
            ip = fields.IPv4(missing=None, default=None, allow_none=True)
            ip_binary = fields.String(
                load_only=True, missing=None, default=None, data_key="ipBinary"
            )
            records = fields.Nested(
                lambda: HiveLibrary.Record.Schema,
                many=True,
                missing=[],
                default=[],
            )
            names = fields.Nested(
                lambda: HiveLibrary.Host.Name.Schema,
                many=True,
                data_key="hostnames",
                missing=[],
                default=[],
            )
            ports = fields.Nested(
                lambda: HiveLibrary.Host.Port.Schema,
                many=True,
                missing=[],
                default=[],
            )
            sources = fields.Nested(
                lambda: HiveLibrary.Source.Schema,
                many=True,
                missing=[],
                default=[],
            )
            tags = fields.Nested(
                lambda: HiveLibrary.Tag.Schema,
                many=True,
                data_key="tags",
                missing=[],
                default=[],
            )

            class Meta:
                unknown = EXCLUDE

            @post_dump(pass_many=False)
            def parse_host(self, data, many, **kwargs):
                if data["ip"] is not None:
                    data["ipv4"] = data["ip"]
                del data["ip"]
                return data

            @pre_load(pass_many=False)
            def pre_make_records(self, data, **kwargs):
                if "records" in data:
                    if isinstance(data["records"], Dict):
                        records: Dict[str, List] = data["records"]
                        new_records: List[Dict] = list()
                        for key, value_list in records.items():
                            for value in value_list:
                                new_records.append(value)
                        data["records"] = new_records
                if "ip" in data:
                    if data["ip"] == "":
                        data["ip"] = None
                return data

            @post_load
            def make_host(self, data, **kwargs):

                return HiveLibrary.Host(**data)

        @dataclass
        class Name:
            checkmarks: Optional[List["HiveLibrary.Checkmark"]] = field(
                default_factory=lambda: []
            )
            files: Optional[List["HiveLibrary.File"]] = field(
                default_factory=lambda: []
            )
            id: Optional[int] = None
            ips: Optional[List["HiveLibrary.IP"]] = None
            uuid: Optional[UUID] = None
            notes: Optional[List["HiveLibrary.Note"]] = field(
                default_factory=lambda: []
            )
            hostname: Optional[str] = None
            records: Optional[List["HiveLibrary.Record"]] = field(
                default_factory=lambda: []
            )
            sources: Optional[List["HiveLibrary.Source"]] = field(
                default_factory=lambda: []
            )
            tags: Optional[List["HiveLibrary.Tag"]] = field(default_factory=lambda: [])

            class Schema(MarshmallowSchema):
                checkmarks = fields.Nested(
                    lambda: HiveLibrary.Checkmark.Schema,
                    load_only=True,
                    many=True,
                    data_key="checkmarks",
                    missing=[],
                    default=[],
                )
                files = fields.Nested(
                    lambda: HiveLibrary.File.Schema,
                    many=True,
                    data_key="files",
                    missing=[],
                    default=[],
                    allow_none=True,
                )
                id = fields.Integer(
                    load_only=True, missing=None, default=None, data_key="id"
                )
                ips = fields.Nested(
                    lambda: HiveLibrary.IP.Schema,
                    many=True,
                    data_key="ips",
                    missing=[],
                    default=[],
                    allow_none=True,
                    load_only=True,
                )
                uuid = fields.UUID(
                    load_only=True, missing=None, default=None, data_key="uuid"
                )
                notes = fields.Nested(
                    lambda: HiveLibrary.Note.Schema,
                    load_only=True,
                    many=True,
                    data_key="notes",
                    missing=[],
                    default=[],
                    allow_none=True,
                )
                hostname = fields.String(data_key="hostname", missing=None)
                records = fields.Nested(
                    lambda: HiveLibrary.Record.Schema,
                    many=True,
                    data_key="records",
                    missing=[],
                    default=[],
                )
                sources = fields.Nested(
                    lambda: HiveLibrary.Source.Schema,
                    many=True,
                    missing=[],
                    default=[],
                )
                tags = fields.Nested(
                    lambda: HiveLibrary.Tag.Schema,
                    many=True,
                    data_key="tags",
                    missing=[],
                    default=[],
                    allow_none=True,
                )

                class Meta:
                    unknown = EXCLUDE

                @pre_load(pass_many=False)
                def pre_make_records(self, data, **kwargs):
                    if "records" in data:
                        if isinstance(data["records"], Dict):
                            records: Dict[str, List] = data["records"]
                            new_records: List[Dict] = list()
                            for key, value_list in records.items():
                                for value in value_list:
                                    new_records.append(value)
                            data["records"] = new_records
                    return data

                @post_load
                def make_hostname(self, data, **kwargs):
                    return HiveLibrary.Host.Name(**data)

        @dataclass
        class Port:
            ip: Optional[IPv4Address] = None
            checkmarks: Optional[List["HiveLibrary.Checkmark"]] = field(
                default_factory=lambda: []
            )
            files: Optional[List["HiveLibrary.File"]] = field(
                default_factory=lambda: []
            )
            id: Optional[int] = None
            uuid: Optional[UUID] = None
            notes: Optional[List["HiveLibrary.Note"]] = field(
                default_factory=lambda: []
            )
            port: Optional[int] = None
            service: Optional["HiveLibrary.Host.Port.Service"] = None
            protocol: str = "tcp"
            state: str = "open"
            records: Optional[List["HiveLibrary.Record"]] = field(
                default_factory=lambda: []
            )
            sources: Optional[List["HiveLibrary.Source"]] = field(
                default_factory=lambda: []
            )
            tags: Optional[List["HiveLibrary.Tag"]] = field(default_factory=lambda: [])

            class Schema(MarshmallowSchema):
                ip = fields.IPv4(missing=None, default=None)
                checkmarks = fields.Nested(
                    lambda: HiveLibrary.Checkmark.Schema,
                    load_only=True,
                    many=True,
                    missing=[],
                    default=[],
                )
                files = fields.Nested(
                    lambda: HiveLibrary.File.Schema,
                    many=True,
                    missing=[],
                    default=[],
                    allow_none=True,
                )
                id = fields.Integer(load_only=True, missing=None, default=None)
                uuid = fields.UUID(load_only=True, missing=None, default=None)
                notes = fields.Nested(
                    lambda: HiveLibrary.Note.Schema,
                    load_only=True,
                    many=True,
                    missing=[],
                    default=[],
                    allow_none=True,
                )
                port = fields.Integer(missing=None)
                service = fields.Nested(
                    lambda: HiveLibrary.Host.Port.Service.Schema,
                    missing=[],
                    default=[],
                )
                protocol = fields.String(missing=None, default="tcp")
                state = fields.String(missing=None, default="open")
                records = fields.Nested(
                    lambda: HiveLibrary.Record.Schema,
                    many=True,
                    missing=[],
                    default=[],
                )
                sources = fields.Nested(
                    lambda: HiveLibrary.Source.Schema,
                    many=True,
                    missing=[],
                    default=[],
                )
                tags = fields.Nested(
                    lambda: HiveLibrary.Tag.Schema,
                    many=True,
                    missing=[],
                    default=[],
                    allow_none=True,
                )

                class Meta:
                    unknown = EXCLUDE

                @pre_load(pass_many=False)
                def pre_make_records(self, data, **kwargs):
                    if "records" in data:
                        if isinstance(data["records"], Dict):
                            records: Dict[str, List] = data["records"]
                            new_records: List[Dict] = list()
                            for key, value_list in records.items():
                                for value in value_list:
                                    new_records.append(value)
                            data["records"] = new_records
                    return data

                @post_load
                def make_port(self, data, **kwargs):
                    return HiveLibrary.Host.Port(**data)

            @dataclass
            class Service:
                name: Optional[str] = None
                product: Optional[str] = None
                version: Optional[str] = None
                cpelist: Optional[str] = None

                class Schema(MarshmallowSchema):
                    name = fields.String(missing=None)
                    product = fields.String(missing=None)
                    version = fields.String(missing=None)
                    cpelist = fields.String(missing=None)

                    @post_dump(pass_many=False)
                    def clean_missing(self, data, many, **kwargs):
                        clean_data = data.copy()
                        for key in filter(lambda key: data[key] is None, data):
                            del clean_data[key]
                        return clean_data

                    @post_load
                    def make_service(self, data, **kwargs):
                        return HiveLibrary.Host.Port.Service(**data)

    @staticmethod
    def load_config() -> Config:
        config: HiveLibrary.Config = HiveLibrary.Config()
        if path.isfile(config.file) and path.getsize(config.file) > 0:
            with open(config.file, "r") as config_file:
                config_dict: Dict[str, str] = safe_load(config_file)
                config = HiveLibrary.Config.Schema().load(config_dict)
        return config

    @staticmethod
    def dump_config(config: Config) -> None:
        hive_config_dir: str = path.dirname(config.file)
        if not path.isdir(hive_config_dir):
            makedirs(hive_config_dir)
        with open(config.file, "w") as config_file:
            config_dict: Dict[str, str] = HiveLibrary.Config.Schema().dump(config)
            safe_dump(config_dict, config_file)
