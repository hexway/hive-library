# Description
"""
Hive REST API library
Author: HexWay
License: MIT
Copyright 2021, HexWay
"""

# Import
from hive_library import HiveLibrary
from requests import Session, Response, exceptions
from typing import List, Dict, Union, Optional
from uuid import UUID
from dataclasses import dataclass
from datetime import date, timedelta
from json.decoder import JSONDecodeError
from ipaddress import IPv4Address

# Authorship information
__author__ = "HexWay"
__copyright__ = "Copyright 2021, HexWay"
__credits__ = [""]
__license__ = "MIT"
__version__ = "0.0.1b1"
__maintainer__ = "HexWay"
__email__ = "contact@hexway.io"
__status__ = "Development"


# Class AuthenticationError
class AuthenticationError(Exception):
    def __init__(self, message, errors):
        # Call the base class constructor with the parameters it needs
        super().__init__(message)

        # Now for your custom code...
        self.errors = errors


# Class HiveEndpoints
@dataclass
class HiveEndpoints:
    home: str = "/"
    auth: str = "/api/session"
    project: str = "/api/project"
    groups: str = "/api/groups"


# Class HiveRestApi
class HiveRestApi:
    # Set variables

    _endpoints: HiveEndpoints = HiveEndpoints()

    # Init
    def __init__(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        cookie: Optional[str] = None,
        server: Optional[str] = None,
        proxy: Optional[str] = None,
        project_id: Optional[UUID] = None,
        debug: bool = False,
    ) -> None:
        """
        Init HiveRestApi Class
        @param server: Hive server URL string, example: 'http://hive.corp.com:80'
        @param username: Hive username string, example: 'user@mail.com'
        @param password: Hive password string, example: 'Password'
        @param proxy: HTTP Proxy URL string, example: http://127.0.0.1:8080
        @param cookie: Hive cookie string, example: 'SESSIONID=5025db17-a019-4980-9b15-0ffc71a7d0bd'
        @param project_id: Project identifier UUID, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @param debug: Run debug mode or not
        """

        # Load variables from config yaml
        config: HiveLibrary.Config = HiveLibrary.load_config()

        # Get server url from config
        if server is None:
            server = config.server

        # Check server is not None
        if server is None:
            print(
                "Hive server URL is not set! Please set server URL, example: 'http://hive.corp.com:80'"
            )
            exit(1)
        else:
            config.server = server

        # Get cookie, username, password from config
        if cookie is None:
            cookie = config.cookie
        if username is None:
            username = config.username
        if password is None:
            password = config.password

        # Save project id to config file
        if project_id is not None:
            config.project_id = project_id

        # Set internal class variables
        self._server = server
        self._debug = debug
        self._session: Session = Session()
        self._session.headers.update(
            {
                "User-Agent": "Hive Client/" + "0.0.1b1",
                "Accept": "application/json",
                "Connection": "close",
            }
        )

        # Set proxy
        if proxy is None:
            proxy = config.proxy
        if proxy is not None:
            self._session.proxies.update(
                {
                    "http": proxy,
                    "https": proxy,
                }
            )
            config.proxy = proxy

        # Authenticate
        try:
            # Check cookie
            if cookie is not None:
                if not self._check_cookie(cookie):
                    if username is not None and password is not None:
                        self._user: Optional[HiveLibrary.User] = self._password_auth(
                            username, password
                        )
                        if self._user is None:
                            raise AuthenticationError(
                                message="Bad creds", errors="Hive REST API auth error"
                            )
                        else:
                            config.username = username
                            config.password = password
                            config.cookie = self._get_cookie()
                    else:
                        raise AuthenticationError(
                            message="Bad cookie", errors="Hive REST API auth error"
                        )
                else:
                    config.cookie = cookie
            # Check username and password
            elif username is not None and password is not None:
                self._user: Optional[HiveLibrary.User] = self._password_auth(
                    username, password
                )
                if self._user is None:
                    raise AuthenticationError(
                        message="Bad username and/or password",
                        errors="Hive REST API auth error",
                    )
                else:
                    config.username = username
                    config.password = password
                    config.cookie = self._get_cookie()
            # Cookie and creds not presented
            else:
                raise AuthenticationError(
                    message="Not found creds or cookies! Please set cookie or username and password.",
                    errors="Hive REST API auth error",
                )

            # Dump variables to config yaml
            HiveLibrary.dump_config(config=config)
        except exceptions.ProxyError as Error:
            print(f"Proxy error: {Error.args[0]}")
        except exceptions.ConnectionError as Error:
            print(f"Connection error: {Error.args[0]}")

    # Internal methods
    @staticmethod
    def _make_error_string(response: Response) -> str:
        return (
            f"\nRequest: {response.request.method} {response.request.url}"
            + f"\nRequest body: {response.request.body}"
            + f"\nResponse status code: {response.status_code}"
            + f"\nResponse headers: {response.headers}"
            + f"\nResponse body: {response.text}"
        )

    def _get_cookie(self) -> str:
        return f'SESSIONID={self._session.cookies.get("SESSIONID")}'

    # Auth
    def _password_auth(
        self, username: str, password: str
    ) -> Optional[HiveLibrary.User]:
        """
        Authorize by username(email) and password on Hive server
        :param username: Hive username string, example: 'user@mail.com'
        :param password: Hive password string, example: 'Password'
        :return: None if error or User object, example:
        HiveLibrary.User(create_date=datetime.datetime(2021, 4, 22, 10, 5, 1, 557699),
                  email='test@mail.com', id=UUID('f04ba8c3-8224-4b3f-b167-b8939ea4f049'),
                  is_admin=True, is_confirmed=True,
                  last_confirmed=datetime.datetime(2021, 4, 22, 10, 5, 1, 925415),
                  login='test@mail.com', name='test@mail.com')
        """
        try:
            response: Response = self._session.post(
                self._server + self._endpoints.auth,
                json={"userEmail": username, "userPassword": password},
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in authorize by user/pass {error_string}"
            assert isinstance(
                response.json(), Dict
            ), f"Bad response in authorize by user/pass {error_string}"
            user_schema: HiveLibrary.User.Schema = HiveLibrary.User.Schema()
            user: HiveLibrary.User = user_schema.load(response.json())
            return user
        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None
        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    def _check_cookie(self, cookie: str) -> bool:
        """
        Authorize cookie
        :param cookie: Hive cookie string, example: 'SESSIONID=5025db17-a019-4980-9b15-0ffc71a7d0bd'
        :return: True if success or False if error
        """
        self._session.cookies.clear()
        self._session.headers.update({"Cookie": cookie})
        response = self._session.get(self._server + self._endpoints.auth)
        return True if response.status_code == 200 else False

    # Get methods
    def get_groups(self) -> Optional[List[HiveLibrary.Group]]:
        """
        Get groups
        :return: None if error or HiveLibrary.Group object, example:
        [HiveLibrary.Group(children=[], create_date=datetime.datetime(2021, 5, 17, 12, 40, 43, 74198),
                           description='default group', full_slug='/default',
                           id=UUID('83f436b8-14fb-40a0-a794-657f600f645a'),
                           last_updated=datetime.datetime(2021, 5, 17, 12, 40, 43, 74198),
                           name='default', parent_id=None, permission_type=None, projects=[], slug='default',
                           users=[HiveLibrary.User(create_date=None, email='test1@test.com',
                                                   id=UUID('aa30af62-649d-43f2-aa51-338b1eac9409'),
                                                   is_admin=False, is_confirmed=False, last_confirmed=None,
                                                   login=None, name='system', permission_type='EDIT', user=None)])]
        """
        try:
            response = self._session.get(
                self._server + self._endpoints.groups + "/list"
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in get groups {error_string}"
            assert isinstance(
                response.json(), List
            ), f"Bad response in get groups {error_string}"
            group_schema: HiveLibrary.Group.Schema = HiveLibrary.Group.Schema(many=True)
            groups: List[HiveLibrary.Group] = group_schema.load(response.json())
            return groups
        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None
        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    def get_projects_list(self) -> Optional[List[HiveLibrary.Project]]:
        """
        Get projects list
        @return: None if error or Projects list, example:
        [HiveLibrary.Project(projectArchiveDate=None, projectConnectionId=None, projectCreateDate='2021-05-20T16:43:45.895024Z',
                      projectDescription='Unit test project', projectEndDate='2021-01-21T00:00:00.000000Z',
                      projectFullSlug='/default/test_project', projectGroupId='83f436b8-14fb-40a0-a794-657f600f645a',
                      projectId='a4f4f8e5-df18-41ed-9b91-59156ef7f053', projectIsArchived=False,
                      projectName='test_project', projectPermission='ADMIN', projectScope=None,
                      projectSlug='test_project', projectStartDate='2021-01-01T00:00:00.000000Z', projectUsers=None)]
        """
        try:
            response: Response = self._session.get(
                self._server + self._endpoints.project
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in get projects {error_string}"
            assert isinstance(
                response.json(), List
            ), f"Bad response in get projects {error_string}"
            project_schema: HiveLibrary.Project.Schema = HiveLibrary.Project.Schema(
                many=True
            )
            projects: List[HiveLibrary.Project] = project_schema.load(response.json())
            return projects
        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None
        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    def get_task(self, project_id: UUID, task_id: UUID) -> Optional[HiveLibrary.Task]:
        """
        Get task information by project id and task id
        @param project_id: Project identifier UUID, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @param task_id: Task identifier UUID, example: 'd2ac8146-d9a8-4b38-86b9-b31f20997586'
        @return: None if error or Task object, example:
        HiveLibrary.Task(id=UUID('4ebfb427-f570-4f8c-b6ca-b854c6f46f0d'), type='api_import',
                  user_id=UUID('f04ba8c3-8224-4b3f-b167-b8939ea4f049'),
                  project_id=UUID('05000d7a-d085-48c2-8ffc-24676ee5cdde'),
                  data_source_id=None, file_id=None, file_uuid=None, file_name=None, file_node_id=None,
                  timestamp=datetime.datetime(2021, 5, 24, 8, 48, 26, 705634), state='PROGRESS', total=1, current=0)
        """
        try:
            response = self._session.get(
                self._server
                + self._endpoints.project
                + f"/{project_id}/tasks/{task_id}"
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in create project {error_string}"
            assert isinstance(
                response.json(), Dict
            ), f"Bad response in get task {error_string}"
            task_schema: HiveLibrary.Task.Schema = HiveLibrary.Task.Schema()
            task: HiveLibrary.Task = task_schema.load(response.json())
            return task
        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None
        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    def get_task_state(self, project_id: UUID, task_id: UUID) -> Optional[str]:
        """
        Get task state by task id
        :param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        :param task_id: Task identifier string, example: 'd2ac8146-d9a8-4b38-86b9-b31f20997586'
        :return: None if error or task state string, example: 'SUCCESS'
        """
        task: Optional[HiveLibrary.Task] = self.get_task(
            project_id=project_id, task_id=task_id
        )
        if isinstance(task, HiveLibrary.Task):
            return task.state
        else:
            return None

    def task_is_completed(self, project_id: UUID, task_id: UUID) -> bool:
        """
        Check task is completed by task identifier
        @param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @param task_id: Task identifier string, example: 'd2ac8146-d9a8-4b38-86b9-b31f20997586'
        @return: True if task is completed or False if task isn't completed or error
        """
        task_state: Optional[str] = self.get_task_state(
            project_id=project_id, task_id=task_id
        )
        if task_state == "SUCCESS":
            return True
        else:
            return False

    def get_ip_labels_for_project(
        self, project_id: UUID
    ) -> Optional[List[HiveLibrary.Label]]:
        """
        Get IP labels for project
        @param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @return: None if error or list of labels, example: [HiveLibrary.Label(count=1, label='192.168.1.1')]
        """
        try:
            response = self._session.get(
                self._server
                + self._endpoints.project
                + f"/{project_id}/graph/nodes/info?label=ip"
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in get ip labels {error_string}"
            assert isinstance(
                response.json(), List
            ), f"Bad response in get ip labels {error_string}"
            label_schema: HiveLibrary.Label.Schema = HiveLibrary.Label.Schema(many=True)
            labels: List[HiveLibrary.Label] = label_schema.load(response.json())
            return labels
        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None
        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    def get_port_labels_for_project(
        self, project_id: UUID
    ) -> Optional[List[HiveLibrary.Label]]:
        """
        Get port labels for project
        @param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @return: None if error or list of labels, example: [HiveLibrary.Label(count=1, label=80)]
        """
        try:
            response = self._session.get(
                self._server
                + self._endpoints.project
                + f"/{project_id}/graph/nodes/info?label=port"
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in get port labels {error_string}"
            assert isinstance(
                response.json(), List
            ), f"Bad response in get port labels {error_string}"
            label_schema: HiveLibrary.Label.Schema = HiveLibrary.Label.Schema(many=True)
            labels: List[HiveLibrary.Label] = label_schema.load(response.json())
            return labels
        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None
        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    def get_hosts(self, project_id: UUID) -> Optional[List[HiveLibrary.Host]]:
        """
        Get hosts
        @param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @return: None if error or List of hosts, example:
        [HiveLibrary.Host(checkmarks=[], files=[], id=106, uuid=UUID('cc862d8d-39ad-49fa-918f-3762847ecdf2'),
                   notes=None, ip=IPv4Address('192.168.1.1'), records=[],
                   hostnames=[HiveLibrary.Host.Name(checkmarks=[], files=[], id=182,
                              uuid=UUID('459240f7-9825-45ca-af4b-86bcb4ac5b0c'), notes=None,
                              hostname='unit.test.com', records=[],
                              tags=[HiveLibrary.Tag(id=186, uuid=None, name='hostname_tag')])],
                   ports=[HiveLibrary.Host.Port(checkmarks=[], files=[], id=190,
                          uuid=UUID('4ad7c296-995b-4890-a470-5191708b087b'), notes=None, port=1234,
                          service=HiveLibrary.Host.Port.Service(name='unit test service name',
                                                         product='unit test service name',
                                                         version='0.1',
                                                         cpelist='unit test service cpelist'),
                          protocol='tcp', state='open', records=[],
                          tags=[HiveLibrary.Tag(id=192, uuid=UUID('03db99e5-3fa4-452d-95d9-f3982b9c641f'), name='port_tag')])],
                   tags=[HiveLibrary.Tag(id=188, uuid=None, name='host_tag')])]
        """
        try:
            response = self._session.get(
                self._server + self._endpoints.project + f"/{project_id}/graph"
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in get hosts {error_string}"
            assert isinstance(
                response.json(), List
            ), f"Bad response in get hosts {error_string}"
            host_schema: HiveLibrary.Project.Schema = HiveLibrary.Host.Schema(many=True)
            hosts: List[HiveLibrary.Host] = host_schema.load(response.json())
            return hosts

        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None

        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    def get_file(self, project_id: UUID, file_uuid: UUID) -> Optional[bytes]:
        """
        Get file content from project ID by file uuid
        @param project_id: Project ID string, example: 24a6c90f-dd0b-4b25-bfbe-09784fc3b4ea
        @param file_uuid: File UUID string, example: 66717b2e-9046-4a17-9928-590393a823d4
        @return: Bytes of file content or None if error
        """
        response = self._session.get(
            self._server
            + self._endpoints.project
            + f"/{project_id}/graph/file/{file_uuid}"
        )
        return response.content if response.status_code == 200 else None

    def get_ip_id(
        self, project_id: UUID, ip: IPv4Address = IPv4Address("127.0.0.1")
    ) -> Optional[int]:
        """
        Get node identifier by IP address
        @param project_id: Project ID string, example: '24a6c90f-dd0b-4b25-bfbe-09784fc3b4ea'
        @param ip: IP address, example: '127.0.0.1'
        @return: IP node identifier integer, example: 123 or None if error
        """
        hosts: Optional[List[HiveLibrary.Host]] = self.get_hosts(project_id=project_id)
        if isinstance(hosts, list):
            for host in hosts:
                if host.ip == ip:
                    return host.id
        return None

    def get_port_id(
        self,
        project_id: UUID,
        ip: IPv4Address = IPv4Address("127.0.0.1"),
        port: int = 22,
    ) -> Optional[int]:
        """
        Get node identifier by port number
        @param project_id: Project ID string, example: '24a6c90f-dd0b-4b25-bfbe-09784fc3b4ea'
        @param ip: IP address, example: '127.0.0.1'
        @param port: Port number integer, example: 22
        @return: Port node identifier integer, example: 123 or None if error
        """
        hosts: Optional[List[HiveLibrary.Host]] = self.get_hosts(project_id=project_id)
        if isinstance(hosts, list):
            for host in hosts:
                if host.ip == ip:
                    for host_port in host.ports:
                        if host_port.port == port:
                            return host_port.id
        return None

    def get_project_id_by_name(self, project_name: str) -> Optional[UUID]:
        """
        Get project identifier by name
        @param project_name: Project name string, example: 'project_name'
        @return: Project identifier string or None if error, example: 'be282469-5615-493b-842b-733e6f0b015a'
        """
        projects_list: List[HiveLibrary.Project] = self.get_projects_list()
        for project in projects_list:
            if project.name == project_name and project_name != "":
                return project.id
        return None

    def get_host(self, project_id: UUID, host_id: int) -> Optional[HiveLibrary.Host]:
        """
        Get host by id
        @param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @param host_id: Host identifier integer, example: 123
        @return: None if error or Host object, example:
        HiveLibrary.Host(checkmarks=[], files=[], id=106, uuid=UUID('cc862d8d-39ad-49fa-918f-3762847ecdf2'),
                   notes=None, ip=IPv4Address('192.168.1.1'), records=[],
                   hostnames=[HiveLibrary.Host.Name(checkmarks=[], files=[], id=182,
                              uuid=UUID('459240f7-9825-45ca-af4b-86bcb4ac5b0c'), notes=None,
                              hostname='unit.test.com', records=[],
                              tags=[HiveLibrary.Tag(id=186, uuid=None, name='hostname_tag')])],
                   ports=[HiveLibrary.Host.Port(checkmarks=[], files=[], id=190,
                          uuid=UUID('4ad7c296-995b-4890-a470-5191708b087b'), notes=None, port=1234,
                          service=HiveLibrary.Host.Port.Service(name='unit test service name',
                                                         product='unit test service name',
                                                         version='0.1',
                                                         cpelist='unit test service cpelist'),
                          protocol='tcp', state='open', records=[],
                          tags=[HiveLibrary.Tag(id=192, uuid=UUID('03db99e5-3fa4-452d-95d9-f3982b9c641f'), name='port_tag')])],
                   tags=[HiveLibrary.Tag(id=188, uuid=None, name='host_tag')])
        """
        try:
            response = self._session.get(
                self._server
                + self._endpoints.project
                + f"/{project_id}/graph/nodes/{host_id}"
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in get host {error_string}"
            assert isinstance(
                response.json(), Dict
            ), f"Bad response in get host {error_string}"
            host_schema: HiveLibrary.Host.Schema = HiveLibrary.Host.Schema()
            host: HiveLibrary.Host = host_schema.load(response.json())
            return host

        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None

        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    def get_hostname(
        self, project_id: UUID, hostname_id: int
    ) -> Optional[HiveLibrary.Host.Name]:
        """
        Get hostname by id
        @param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @param hostname_id: Hostname identifier integer, example: 123
        @return: None if error or Hostname object, example:
        HiveLibrary.Host.Name(checkmarks=[], files=[], id=124,
                              ips=[HiveLibrary.IP(id=118, ip=IPv4Address('192.168.1.1'), ports=None, tags=None,
                                                  uuid=UUID('edde5d46-a8c5-48c9-9c23-af49e76b0ca1'))],
                              uuid=UUID('21cb06ad-6447-4f25-8ab2-5b21df17a8b8'), notes=None, hostname='unit.test.com',
                              records=[HiveLibrary.Record(children=[],
                                                          create_time=datetime.datetime(2021, 6, 8, 14, 14, 59, 888471),
                                                          creator_uuid=None, extra=None, id=128, uuid=None,
                                                          import_type='unit_test_tool_name',
                                                          name='unit test list hostname record',
                                                          tool_name=None, record_type='list',
                                                          value=['unit test list hostname record value 1',
                                                                 'unit test list hostname record value 2'])],
                              sources=[HiveLibrary.Source(comment=None,
                                                          creator_uuid=UUID('f04ba8c3-8224-4b3f-b167-b8939ea4f049'),
                                                          filename='api_upload', id=114, import_status='Success',
                                                          labels=['Datasource'], name=None,
                                                          post_time=datetime.datetime(2021, 6, 8, 14, 14, 59, 888471),
                                                          type='api', uuid=UUID('1cecbd4c-610b-48ea-9aba-cd6a02537218'))],
                              tags=[HiveLibrary.Tag(id=127, uuid=UUID('8ecae7c0-2024-4332-9ce5-54d539d3e595'),
                                                    name='hostname_tag', parent_id=None, base_node_id=None, labels=[],
                                                    parent_labels=[])])
        """
        try:
            response = self._session.get(
                self._server
                + self._endpoints.project
                + f"/{project_id}/graph/nodes/{hostname_id}"
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in get hostname {error_string}"
            assert isinstance(
                response.json(), Dict
            ), f"Bad response in get hostname {error_string}"
            hostname_schema: HiveLibrary.Host.Name.Schema = (
                HiveLibrary.Host.Name.Schema()
            )
            hostname: HiveLibrary.Host.Name = hostname_schema.load(response.json())
            return hostname

        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None

        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    def get_port(
        self, project_id: UUID, port_id: int
    ) -> Optional[HiveLibrary.Host.Port]:
        """
        Get port by id
        @param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @param port_id: Port identifier integer, example: 123
        @return: None if error or Port object, example:
        HiveLibrary.Host.Port(ip=IPv4Address('192.168.1.1'), checkmarks=[], files=[], id=132,
                              uuid=UUID('3ba90ac2-7c28-4385-b89d-cf3173ed393a'), notes=None, port=12345,
                              service=HiveLibrary.Host.Port.Service(name='http', product='Unit test',
                                                                    version='0.1', cpelist='unit test service cpelist'),
                              protocol='tcp', state='open',
                              records=[HiveLibrary.Record(children=[ .... ],
                                       create_time=datetime.datetime(2021, 6, 8, 14, 43, 59, 271652),
                                       creator_uuid=None, extra=None, id=135, uuid=None,
                                       import_type='unit_test_tool_name', name='unit test nested port record',
                                       tool_name=None, record_type='nested',
                                       value=[ .... ],
                              sources=[HiveLibrary.Source(comment=None,
                                                          creator_uuid=UUID('f04ba8c3-8224-4b3f-b167-b8939ea4f049'),
                                                          filename='api_upload', id=114, import_status='Success',
                                                          labels=['Datasource'], name=None,
                                                          post_time=datetime.datetime(2021, 6, 8, 14, 43, 59, 271652),
                                                          type='api', uuid=UUID('6b08ca3e-706f-4ccf-915a-daced88e97d5'))],
                              tags=[HiveLibrary.Tag(id=134, uuid=None, name='port_tag', parent_id=None,
                                    base_node_id=None, labels=[], parent_labels=[])])
        """
        try:
            response = self._session.get(
                self._server
                + self._endpoints.project
                + f"/{project_id}/graph/nodes/{port_id}"
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in get port {error_string}"
            assert isinstance(
                response.json(), Dict
            ), f"Bad response in get port {error_string}"
            port_schema: HiveLibrary.Host.Port.Schema = HiveLibrary.Host.Port.Schema()
            port: HiveLibrary.Host.Port = port_schema.load(response.json())
            return port

        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None

        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    # Search methods
    def search(
        self, project_id: UUID, search_string: str
    ) -> Optional[List[HiveLibrary.Host]]:
        """
        Search hosts in project
        :param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        :param search_string: Search string, example: 'ip == 127.0.0.1 and port == 22'
        :return: None if error or Hosts list, example:
        [HiveLibrary.Host(checkmarks=[], files=[], id=106, uuid=UUID('cc862d8d-39ad-49fa-918f-3762847ecdf2'),
                   notes=None, ip=IPv4Address('192.168.1.1'), records=[],
                   hostnames=[HiveLibrary.Host.Name(checkmarks=[], files=[], id=182,
                              uuid=UUID('459240f7-9825-45ca-af4b-86bcb4ac5b0c'), notes=None,
                              hostname='unit.test.com', records=[],
                              tags=[HiveLibrary.Tag(id=186, uuid=None, name='hostname_tag')])],
                   ports=[HiveLibrary.Host.Port(checkmarks=[], files=[], id=190,
                          uuid=UUID('4ad7c296-995b-4890-a470-5191708b087b'), notes=None, port=1234,
                          service=HiveLibrary.Host.Port.Service(name='unit test service name',
                                                         product='unit test service name',
                                                         version='0.1',
                                                         cpelist='unit test service cpelist'),
                          protocol='tcp', state='open', records=[],
                          tags=[HiveLibrary.Tag(id=192, uuid=UUID('03db99e5-3fa4-452d-95d9-f3982b9c641f'), name='port_tag')])],
                   tags=[HiveLibrary.Tag(id=188, uuid=None, name='host_tag')])]
        """
        try:
            response = self._session.post(
                self._server + self._endpoints.project + f"/{project_id}/graph/search",
                json={"searchString": search_string},
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in search: {search_string} {error_string}"
            assert isinstance(
                response.json(), List
            ), f"Bad response in search: {search_string} {error_string}"
            host_schema: HiveLibrary.Project.Schema = HiveLibrary.Host.Schema(many=True)
            hosts: List[HiveLibrary.Host] = host_schema.load(response.json())
            return hosts
        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None
        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    def search_by_ip(
        self, project_id: UUID, ip: Union[IPv4Address, List[IPv4Address]]
    ) -> Optional[List[HiveLibrary.Host]]:
        """
        Get all hosts by IP address or IP addresses list
        @param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @param ip: IP address string or IP addresses list, example: '1.1.1.1' or ['1.1.1.1', '8.8.8.8']
        @return: None if error or Hosts list, example:
        [HiveLibrary.Host(checkmarks=[], files=[], id=106, uuid=UUID('cc862d8d-39ad-49fa-918f-3762847ecdf2'),
                   notes=None, ip=IPv4Address('192.168.1.1'), records=[],
                   hostnames=[HiveLibrary.Host.Name(checkmarks=[], files=[], id=182,
                              uuid=UUID('459240f7-9825-45ca-af4b-86bcb4ac5b0c'), notes=None,
                              hostname='unit.test.com', records=[],
                              tags=[HiveLibrary.Tag(id=186, uuid=None, name='hostname_tag')])],
                   ports=[HiveLibrary.Host.Port(checkmarks=[], files=[], id=190,
                          uuid=UUID('4ad7c296-995b-4890-a470-5191708b087b'), notes=None, port=1234,
                          service=HiveLibrary.Host.Port.Service(name='unit test service name',
                                                         product='unit test service name',
                                                         version='0.1',
                                                         cpelist='unit test service cpelist'),
                          protocol='tcp', state='open', records=[],
                          tags=[HiveLibrary.Tag(id=192, uuid=UUID('03db99e5-3fa4-452d-95d9-f3982b9c641f'), name='port_tag')])],
                   tags=[HiveLibrary.Tag(id=188, uuid=None, name='host_tag')])]
        """
        if isinstance(ip, List):
            for i in range(len(ip)):
                ip[i] = f"ip == '{ip[i]}'"
            search: str = " or ".join(ip)
        else:
            search: str = f"ip == '{ip}'"
        return self.search(project_id, search)

    def search_by_port(
        self, project_id: UUID, port: Union[int, List[int]]
    ) -> Optional[List[HiveLibrary.Host]]:
        """
        Get all hosts by Port or Ports list
        @param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @param port: Port or ports list, example: '22' or ['22', '80']
        @return: None if error or Hosts list, example:
        [HiveLibrary.Host(checkmarks=[], files=[], id=106, uuid=UUID('cc862d8d-39ad-49fa-918f-3762847ecdf2'),
                   notes=None, ip=IPv4Address('192.168.1.1'), records=[],
                   hostnames=[HiveLibrary.Host.Name(checkmarks=[], files=[], id=182,
                              uuid=UUID('459240f7-9825-45ca-af4b-86bcb4ac5b0c'), notes=None,
                              hostname='unit.test.com', records=[],
                              tags=[HiveLibrary.Tag(id=186, uuid=None, name='hostname_tag')])],
                   ports=[HiveLibrary.Host.Port(checkmarks=[], files=[], id=190,
                          uuid=UUID('4ad7c296-995b-4890-a470-5191708b087b'), notes=None, port=1234,
                          service=HiveLibrary.Host.Port.Service(name='unit test service name',
                                                         product='unit test service name',
                                                         version='0.1',
                                                         cpelist='unit test service cpelist'),
                          protocol='tcp', state='open', records=[],
                          tags=[HiveLibrary.Tag(id=192, uuid=UUID('03db99e5-3fa4-452d-95d9-f3982b9c641f'), name='port_tag')])],
                   tags=[HiveLibrary.Tag(id=188, uuid=None, name='host_tag')])]
        """
        if isinstance(port, List):
            for i in range(len(port)):
                port[i] = f"port == {port[i]}"
            search: str = " or ".join(port)
        else:
            search: str = f"port == {port}"
        return self.search(project_id, search)

    def search_by_ip_and_port(
        self, project_id: UUID, ip: IPv4Address, port: int
    ) -> Optional[List[HiveLibrary.Host]]:
        """
        Get all hosts by IP address and Port
        @param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @param port: IP address string, example: '127.0.0.1'
        @param ip: Port number string, example: '22'
        @return: None if error or Hosts list, example:
        [HiveLibrary.Host(checkmarks=[], files=[], id=106, uuid=UUID('cc862d8d-39ad-49fa-918f-3762847ecdf2'),
                   notes=None, ip=IPv4Address('192.168.1.1'), records=[],
                   hostnames=[HiveLibrary.Host.Name(checkmarks=[], files=[], id=182,
                              uuid=UUID('459240f7-9825-45ca-af4b-86bcb4ac5b0c'), notes=None,
                              hostname='unit.test.com', records=[],
                              tags=[HiveLibrary.Tag(id=186, uuid=None, name='hostname_tag')])],
                   ports=[HiveLibrary.Host.Port(checkmarks=[], files=[], id=190,
                          uuid=UUID('4ad7c296-995b-4890-a470-5191708b087b'), notes=None, port=1234,
                          service=HiveLibrary.Host.Port.Service(name='unit test service name',
                                                         product='unit test service name',
                                                         version='0.1',
                                                         cpelist='unit test service cpelist'),
                          protocol='tcp', state='open', records=[],
                          tags=[HiveLibrary.Tag(id=192, uuid=UUID('03db99e5-3fa4-452d-95d9-f3982b9c641f'), name='port_tag')])],
                   tags=[HiveLibrary.Tag(id=188, uuid=None, name='host_tag')])]
        """
        search: str = f"ip == {ip} and port == {port}"
        return self.search(project_id, search)

    def search_by_hostname(
        self, project_id: UUID, hostname: Union[str, List[str]]
    ) -> Optional[List[HiveLibrary.Host]]:
        """
        Get all hosts by Hostname or hostnames list
        @param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @param hostname: Hostname or hostnames list, example: 'test.host.com' or ['test1.host.com', 'test2.host.com']
        @return: None if error or Hosts list, example:
        [HiveLibrary.Host(checkmarks=[], files=[], id=106, uuid=UUID('cc862d8d-39ad-49fa-918f-3762847ecdf2'),
                   notes=None, ip=IPv4Address('192.168.1.1'), records=[],
                   hostnames=[HiveLibrary.Host.Name(checkmarks=[], files=[], id=182,
                              uuid=UUID('459240f7-9825-45ca-af4b-86bcb4ac5b0c'), notes=None,
                              hostname='unit.test.com', records=[],
                              tags=[HiveLibrary.Tag(id=186, uuid=None, name='hostname_tag')])],
                   ports=[HiveLibrary.Host.Port(checkmarks=[], files=[], id=190,
                          uuid=UUID('4ad7c296-995b-4890-a470-5191708b087b'), notes=None, port=1234,
                          service=HiveLibrary.Host.Port.Service(name='unit test service name',
                                                         product='unit test service name',
                                                         version='0.1',
                                                         cpelist='unit test service cpelist'),
                          protocol='tcp', state='open', records=[],
                          tags=[HiveLibrary.Tag(id=192, uuid=UUID('03db99e5-3fa4-452d-95d9-f3982b9c641f'), name='port_tag')])],
                   tags=[HiveLibrary.Tag(id=188, uuid=None, name='host_tag')])]
        """
        if isinstance(hostname, List):
            for i in range(len(hostname)):
                hostname[i] = f"hostname == '{hostname[i]}'"
            search: str = " or ".join(hostname)
        else:
            search: str = f"hostname == '{hostname}'"
        return self.search(project_id, search)

    def search_by_tag(
        self, project_id: UUID, tag: Union[str, List[str]]
    ) -> Optional[List[HiveLibrary.Host]]:
        """
        Get all hosts by Tag or tags list
        @param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @param tag: Tag or tags list, example: 'tag' or ['tag1', 'tag2']
        @return: None if error or Hosts list, example:
        [HiveLibrary.Host(checkmarks=[], files=[], id=106, uuid=UUID('cc862d8d-39ad-49fa-918f-3762847ecdf2'),
                   notes=None, ip=IPv4Address('192.168.1.1'), records=[],
                   hostnames=[HiveLibrary.Host.Name(checkmarks=[], files=[], id=182,
                              uuid=UUID('459240f7-9825-45ca-af4b-86bcb4ac5b0c'), notes=None,
                              hostname='unit.test.com', records=[],
                              tags=[HiveLibrary.Tag(id=186, uuid=None, name='hostname_tag')])],
                   ports=[HiveLibrary.Host.Port(checkmarks=[], files=[], id=190,
                          uuid=UUID('4ad7c296-995b-4890-a470-5191708b087b'), notes=None, port=1234,
                          service=HiveLibrary.Host.Port.Service(name='unit test service name',
                                                         product='unit test service name',
                                                         version='0.1',
                                                         cpelist='unit test service cpelist'),
                          protocol='tcp', state='open', records=[],
                          tags=[HiveLibrary.Tag(id=192, uuid=UUID('03db99e5-3fa4-452d-95d9-f3982b9c641f'), name='port_tag')])],
                   tags=[HiveLibrary.Tag(id=188, uuid=None, name='host_tag')])]
        """
        if isinstance(tag, List):
            for i in range(len(tag)):
                tag[i] = f"tag == '{tag[i]}'"
            search: str = " or ".join(tag)
        else:
            search: str = f"tag == '{tag}'"
        return self.search(project_id, search)

    def search_by_service(
        self, project_id: UUID, service: Union[str, List[str]]
    ) -> Optional[List[HiveLibrary.Host]]:
        """
        Get all hosts by Tag or service or services list
        @param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @param service: Tag or tags list, example: 'ssh' or ['ssh', 'http']
        @return: None if error or Hosts list, example:
        [HiveLibrary.Host(checkmarks=[], files=[], id=106, uuid=UUID('cc862d8d-39ad-49fa-918f-3762847ecdf2'),
                   notes=None, ip=IPv4Address('192.168.1.1'), records=[],
                   hostnames=[HiveLibrary.Host.Name(checkmarks=[], files=[], id=182,
                              uuid=UUID('459240f7-9825-45ca-af4b-86bcb4ac5b0c'), notes=None,
                              hostname='unit.test.com', records=[],
                              tags=[HiveLibrary.Tag(id=186, uuid=None, name='hostname_tag')])],
                   ports=[HiveLibrary.Host.Port(checkmarks=[], files=[], id=190,
                          uuid=UUID('4ad7c296-995b-4890-a470-5191708b087b'), notes=None, port=1234,
                          service=HiveLibrary.Host.Port.Service(name='unit test service name',
                                                         product='unit test service name',
                                                         version='0.1',
                                                         cpelist='unit test service cpelist'),
                          protocol='tcp', state='open', records=[],
                          tags=[HiveLibrary.Tag(id=192, uuid=UUID('03db99e5-3fa4-452d-95d9-f3982b9c641f'), name='port_tag')])],
                   tags=[HiveLibrary.Tag(id=188, uuid=None, name='host_tag')])]
        """
        if isinstance(service, List):
            for i in range(len(service)):
                service[i] = f"service == '{service[i]}'"
            search: str = " or ".join(service)
        else:
            search: str = f"service == '{service}'"
        return self.search(project_id, search)

    # Post methods
    def create_project(
        self,
        project: HiveLibrary.Project,
    ) -> Optional[HiveLibrary.Project]:
        """
        Create new project
        :param project: HiveLibrary.Project object, example: HiveLibrary.Project(projectArchiveDate=None,
                                                                   projectConnectionId=None,
                                                                   projectCreateDate=None,
                                                                   projectDescription='Unit test project',
                                                                   projectEndDate='2021-01-21',
                                                                   projectFullSlug=None,
                                                                   projectGroupId='83f436b8-14fb-40a0-a794-657f600f645a',
                                                                   projectId=None,
                                                                   projectIsArchived=False,
                                                                   projectName='test_project',
                                                                   projectPermission=None,
                                                                   projectScope=None,
                                                                   projectSlug=None,
                                                                   projectStartDate='2021-01-01',
                                                                   projectUsers=None)
        :return: None if error or Project object, example:
        HiveLibrary.Project(projectArchiveDate=None, projectConnectionId=None, projectCreateDate='2021-05-20T16:30:03.120592Z',
                     projectDescription='Unit test project', projectEndDate='2021-01-21T00:00:00.000000Z',
                     projectFullSlug='/default/test_project', projectGroupId='83f436b8-14fb-40a0-a794-657f600f645a',
                     projectId='78171434-ceac-4bca-a1ba-a594a7c795d9', projectIsArchived=False,
                     projectName='test_project', projectPermission='OWNER', projectScope=None,
                     projectSlug='test_project', projectStartDate='2021-01-01T00:00:00.000000Z',
                     projectUsers=[HiveLibrary.Project.User(permissionType='OWNER',
                                                     userEmail='user@mail.com',
                                                     userName='user@mail.com',
                                                     userId='f04ba8c3-8224-4b3f-b167-b8939ea4f049')])
        """
        try:
            if project.start_date is None:
                project.start_date = date.today()
            if project.end_date is None:
                project.end_date = date.today() + timedelta(weeks=1)
            assert (
                project.name is not None
            ), "For create project, please set project Name"
            if project.group_id is None:
                groups: Optional[List[HiveLibrary.Group]] = self.get_groups()
                assert groups is not None, "Failed to get groups for create project"
                project.group_id = groups[0].id
            response: Response = self._session.post(
                self._server + self._endpoints.project,
                json=HiveLibrary.Project.Schema().dump(project),
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in create project {error_string}"
            assert isinstance(
                response.json(), Dict
            ), f"Bad response in create project {error_string}"
            project_schema: HiveLibrary.Project.Schema = HiveLibrary.Project.Schema()
            project: HiveLibrary.Project = project_schema.load(response.json())
            return project
        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None
        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    def import_from_file(
        self,
        file_location: str,
        import_type: str = "nmap",
        project_id: Optional[UUID] = None,
        project_name: Optional[str] = None,
    ) -> Optional[UUID]:
        """
        Import data from file
        :param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        :param project_name: Project name string, example: 'test_project'
        :param import_type: Import type string, examples: 'nmap', 'nessus', 'metasploit', 'cobaltstrike'
        :param file_location: File location string, example: '/tmp/test.xml'
        :return: None if error or import task identifier, example: 'e08d16f3-b864-44ac-a90c-8e10f4af9893'
        """
        try:
            if project_name is None and project_id is None:
                assert False, "Project ID and Name is not set"
            if project_name is not None:
                project_id = self.get_project_id_by_name(project_name=project_name)
            with open(file_location, "r") as file:
                file_content = file.read()
            response = self._session.post(
                self._server
                + self._endpoints.project
                + f"/{project_id}/graph?importType={import_type}",
                data=file_content,
                headers={"Content-Type": "applications/octet-stream"},
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in import from file {error_string}"
            if "taskId" in response.json():
                if isinstance(response.json()["taskId"], str):
                    return UUID(response.json()["taskId"])
            return None
        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None
        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    def create_hosts(
        self, project_id: UUID, hosts: List[HiveLibrary.Host]
    ) -> Optional[UUID]:
        """
        Create hosts in project
        @param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @param hosts: List of hosts, example:
        [HiveLibrary.Host(ipv4='192.168.1.1',
                   records=[HiveLibrary.Host.Record(name='unit test nested host record',
                                             tool_name='unit_test_tool_name',
                                             record_type='nested',
                                             value=[HiveLibrary.Host.Record(name='unit test host record name 1',
                                                                     tool_name='unit_test_tool_name',
                                                                     record_type='string',
                                                                     value='unit test host record value 1'),
                                                   HiveLibrary.Host.Record(name='unit test host record name 2',
                                                                    tool_name='unit_test_tool_name',
                                                                    record_type='string',
                                                                    value='unit test host record value 2')])],
                   hostnames=[HiveLibrary.Host.Hostname(hostname='unit.test.com',
                                                 records=[HiveLibrary.Host.Record(name='unit test list hostname record',
                                                                           tool_name='unit_test_tool_name',
                                                                           record_type='list',
                                                                           value=['unit test list hostname record 1',
                                                                                  'unit test list hostname record 2'])])],
                   ports=[HiveLibrary.Host.Port(port=1234,
                                         service=HiveLibrary.Host.Port.Service(name='unit test service name',
                                                                        product='unit test service name',
                                                                        version='0.1'),
                                         protocol='tcp',
                                         state='open',
                                         records=[HiveLibrary.Host.Record(name='unit test string port record',
                                                                   tool_name='unit_test_tool_name',
                                                                   record_type='string',
                                                                   value='unit test string port record value')])])]
        @return: None if error or import task UUID
        """
        try:
            hosts_schema: HiveLibrary.Host.Schema = HiveLibrary.Host.Schema(many=True)
            response = self._session.post(
                self._server + self._endpoints.project + f"/{project_id}/graph/api",
                json=hosts_schema.dump(hosts),
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in create hosts {error_string}"
            assert isinstance(
                response.json(), Dict
            ), f"Bad response in create hosts {error_string}"
            assert (
                "taskId" in response.json()
            ), f"Not found key taskId in create hosts response {error_string}"
            assert isinstance(
                response.json()["taskId"], str
            ), f"Bad value for key taskId in create hosts response {error_string}"
            return UUID(response.json()["taskId"])
        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None
        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    def create_host(self, project_id: UUID, host: HiveLibrary.Host) -> Optional[UUID]:
        """
        Create host in project
        @param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        @param host: Host object, example:
        HiveLibrary.Host(ipv4='192.168.1.1',
                  records=[HiveLibrary.Host.Record(name='unit test nested host record',
                                            tool_name='unit_test_tool_name',
                                            record_type='nested',
                                            value=[HiveLibrary.Host.Record(name='unit test host record name 1',
                                                                    tool_name='unit_test_tool_name',
                                                                    record_type='string',
                                                                    value='unit test host record value 1'),
                                                  HiveLibrary.Host.Record(name='unit test host record name 2',
                                                                   tool_name='unit_test_tool_name',
                                                                   record_type='string',
                                                                   value='unit test host record value 2')])],
                  hostnames=[HiveLibrary.Host.Hostname(hostname='unit.test.com',
                                                records=[HiveLibrary.Host.Record(name='unit test list hostname record',
                                                                          tool_name='unit_test_tool_name',
                                                                          record_type='list',
                                                                          value=['unit test list hostname record 1',
                                                                                 'unit test list hostname record 2'])])],
                  ports=[HiveLibrary.Host.Port(port=1234,
                                        service=HiveLibrary.Host.Port.Service(name='unit test service name',
                                                                       product='unit test service name',
                                                                       version='0.1'),
                                        protocol='tcp',
                                        state='open',
                                        records=[HiveLibrary.Host.Record(name='unit test string port record',
                                                                  tool_name='unit_test_tool_name',
                                                                  record_type='string',
                                                                  value='unit test string port record value')])])
        @return: None if error or import task UUID
        """
        return self.create_hosts(project_id=project_id, hosts=[host])

    def create_note(
        self, note_text: str, project_id: UUID, node_id: int
    ) -> Optional[HiveLibrary.Note]:
        """
        Create note for node in project
        :param note_text: Note text string, example: 'test'
        :param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        :param node_id: Project identifier integer, example: 123
        :return: None if error or Note object, example:
        HiveLibrary.Note(base_node_id=111, id=129, parent_id=111, type='Node',
                  uuid=UUID('1da9570d-00d7-4044-8d4b-46cdbd7d57b1'),
                  create_time=datetime.datetime(2021, 5, 31, 13, 24, 6, 560968),
                  creator_uuid=UUID('f04ba8c3-8224-4b3f-b167-b8939ea4f049'),
                  files=[], text='unit test note text', node_id=None,
                  checkmarks=[], labels=['Note'], tags=[])
        """
        try:
            response: Response = self._session.post(
                self._server + self._endpoints.project + f"/{project_id}/graph/nodes",
                json=[{"nodeId": node_id, "text": note_text}],
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in create note {error_string}"
            assert isinstance(
                response.json(), List
            ), f"Bad response in create note {error_string}"
            assert (
                len(response.json()) == 1
            ), f"Bad response in create note {error_string}"
            note_schema: HiveLibrary.Note.Schema = HiveLibrary.Note.Schema(many=True)
            note: HiveLibrary.Note = note_schema.load(response.json())[0]
            return note
        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None
        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    def create_tag(
        self, tag_name: str, project_id: UUID, node_id: int
    ) -> Optional[HiveLibrary.Tag]:
        """
        Create tag for node in project
        :param tag_name: Tag name string, example: 'test_tag'
        :param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        :param node_id: Project identifier integer, example: 123
        :return: None if error or Tag object, example:
        HiveLibrary.Tag(id=165, uuid=None, name='unit_test_tag_name',
                 parent_id=145, base_node_id=145,
                 labels=['Tag'], parent_labels=['Ip'])
        """
        try:
            response: Response = self._session.post(
                self._server + self._endpoints.project + f"/{project_id}/graph/nodes",
                json=[{"nodeId": node_id, "tag": tag_name}],
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in create tag {error_string}"
            assert isinstance(
                response.json(), List
            ), f"Bad response in create tag {error_string}"
            assert (
                len(response.json()) == 1
            ), f"Bad response in create tag {error_string}"
            tag_schema: HiveLibrary.Tag.Schema = HiveLibrary.Tag.Schema()
            tag: HiveLibrary.Tag = tag_schema.load(response.json()[0])
            return tag
        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None
        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    def upload_file(
        self,
        file_name: str,
        file_content: bytes,
        project_id: UUID,
        node_id: int,
        file_caption: Optional[str] = None,
    ) -> Optional[HiveLibrary.File]:
        """
        Upload file for node in project
        :param file_name: File name string, example: 'test.txt'
        :param file_content: Bytes of file content, example: b'Hello World!'
        :param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        :param node_id: Project identifier integer, example: 123
        :return: None if error or File object, example:
        HiveLibrary.File(base_node_id=None, caption=None, id=133, type=None,
                  uuid=UUID('b7a2eed4-661f-4797-ad3b-9015bf3e73b7'),
                  post_time=datetime.datetime(2021, 5, 31, 13, 30, 57, 944848),
                  create_time=None, user_uuid=UUID('f04ba8c3-8224-4b3f-b167-b8939ea4f049'), creator_uuid=None,
                  control_sum='sha256:747153e0f6b14eb609fd7cb6921fa871b08f26fec6e042075a2ab30a1af4d295',
                  name='unit_test_file.txt', size=22, mime_type='text/plain', node_id=None, parent_id=111,
                  labels=['File'], parent_labels=['Ip'])
        """
        try:
            response: Response = self._session.post(
                self._server + self._endpoints.project + f"/{project_id}/graph/file",
                data=file_content,
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in upload file {error_string}"
            assert isinstance(
                response.json(), Dict
            ), f"Bad response in upload file {error_string}"
            file_schema: HiveLibrary.File.Schema = HiveLibrary.File.Schema()
            file: HiveLibrary.File = file_schema.load(response.json())
            file.name = file_name
            file.node_id = node_id
            file.caption = file_caption
            response: Response = self._session.post(
                self._server + self._endpoints.project + f"/{project_id}/graph/nodes",
                json=[file_schema.dump(file)],
            )
            assert (
                response.status_code == 200
            ), f"Bad status code in upload file {error_string}"
            assert isinstance(
                response.json(), List
            ), f"Bad response in upload file {error_string}"
            assert (
                len(response.json()) == 1
            ), f"Bad response in create note {error_string}"
            file_schema: HiveLibrary.File.Schema = HiveLibrary.File.Schema()
            file: HiveLibrary.File = file_schema.load(response.json()[0])
            return file
        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None
        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    # Delete methods
    def delete_project_by_id(self, project_id: UUID) -> Optional[HiveLibrary.Project]:
        """
        Delete project by identifier
        :param project_id: Project identifier string, example: 'be282469-5615-493b-842b-733e6f0b015a'
        :return: None if error or Project object, example:
        HiveLibrary.Project(projectArchiveDate=None, projectConnectionId=None, projectCreateDate='2021-05-20T16:30:03.120592Z',
                     projectDescription='Unit test project', projectEndDate='2021-01-21T00:00:00.000000Z',
                     projectFullSlug='/default/test_project', projectGroupId='83f436b8-14fb-40a0-a794-657f600f645a',
                     projectId='78171434-ceac-4bca-a1ba-a594a7c795d9', projectIsArchived=False,
                     projectName='test_project', projectPermission='OWNER', projectScope=None,
                     projectSlug='test_project', projectStartDate='2021-01-01T00:00:00.000000Z',
                     projectUsers=[HiveLibrary.Project.User(permissionType='OWNER',
                                                     userEmail='user@mail.com',
                                                     userName='user@mail.com',
                                                     userId='f04ba8c3-8224-4b3f-b167-b8939ea4f049')])
        """
        try:
            response = self._session.delete(
                self._server + self._endpoints.project + f"/{project_id}"
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                response.status_code == 200
            ), f"Bad status code in delete project {error_string}"
            project_schema: HiveLibrary.Project.Schema = HiveLibrary.Project.Schema()
            project: HiveLibrary.Project = project_schema.load(response.json())
            return project
        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None
        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None

    def delete_project_by_name(self, project_name: str):
        """
        Delete project by name
        :param project_name: Project name string, example: 'msf_project'
        :return: None if error or Project object, example:
        HiveLibrary.Project(projectArchiveDate=None, projectConnectionId=None, projectCreateDate='2021-05-20T16:30:03.120592Z',
                     projectDescription='Unit test project', projectEndDate='2021-01-21T00:00:00.000000Z',
                     projectFullSlug='/default/test_project', projectGroupId='83f436b8-14fb-40a0-a794-657f600f645a',
                     projectId='78171434-ceac-4bca-a1ba-a594a7c795d9', projectIsArchived=False,
                     projectName='test_project', projectPermission='OWNER', projectScope=None,
                     projectSlug='test_project', projectStartDate='2021-01-01T00:00:00.000000Z',
                     projectUsers=[HiveLibrary.Project.User(permissionType='OWNER',
                                                     userEmail='user@mail.com',
                                                     userName='user@mail.com',
                                                     userId='f04ba8c3-8224-4b3f-b167-b8939ea4f049')])
        """
        project_id: Optional[UUID] = None
        projects_list = self.get_projects_list()
        for project in projects_list:
            if project.name == project_name:
                project_id = project.id
        if project_id is None:
            return None
        else:
            return self.delete_project_by_id(project_id=project_id)
