import fnmatch
import json
import logging
import os
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlparse

import requests
from httpie.config import get_default_config_dir
from httpie.plugins import AuthPlugin

__version__ = "0.4.0"
__author__ = "Shane Farmer"


@dataclass
class Credential:
    uid: str
    email: str
    name: str
    avatar: str
    id_token: str
    registered: bool
    refresh_token: str
    expires_in: str
    created: float = field(default_factory=lambda: datetime.now().timestamp())

    def __post_init__(self):
        self.expires = datetime.fromtimestamp(self.created) + timedelta(seconds=int(self.expires_in))

    @property
    def expired(self) -> bool:
        now = datetime.now()
        expire = self.expires - timedelta(seconds=10)
        return now > expire


class FirebaseAuthenticator:
    def __init__(self, email: str, password: str, project: str = None):
        self._email = email
        self._password = password
        self._project = project
        self._config_dir = os.path.join(get_default_config_dir(), "firebase")
        self._cache_dir = os.path.join(self._config_dir, "cache")

        os.makedirs(self._config_dir, exist_ok=True)
        os.makedirs(self._cache_dir, exist_ok=True)

    def __call__(self, req: requests.PreparedRequest) -> requests.PreparedRequest:
        try:
            (project, api_key) = self.__get_api_key(req)
            cache_file = os.path.join(self._cache_dir, "%s.json" % project)

            user: Optional[Credential] = None
            if os.path.isfile(cache_file):
                with open(cache_file, "r") as file:
                    if os.fstat(file.fileno()).st_size:
                        users = json.load(file)
                        if self._email in users:
                            user = Credential(**(users[self._email]))

            if not user:
                logging.info(f">>> Firebase: authenticating user with email and password")
                user = self.__authenticate(api_key)
                if user:
                    self.__write_user(cache_file, user)
            elif user.expired:
                logging.warning(f">>> Firebase: id token has expired, refreshing")
                user = self.__refresh_token(api_key, user)
                if user:
                    self.__write_user(cache_file, user)

            if user:
                req.headers["Authorization"] = "Bearer %s" % user.id_token
            else:
                logging.warning("Could not find user: %s", self._email)
            return req
        except IOError:
            logging.error("Failed to authenticate user request", exc_info=True)

    @staticmethod
    def __write_user(cache_file, user: Credential):
        with open(cache_file, "r+") as file:
            file_str = file.read()
            contents = dict()
            logging.info("file: %s", file)
            logging.info("str: %s", file_str)
            if len(file_str) > 0:
                contents = json.loads(file_str)
                logging.info("Loaded contents from cache: %s", contents)

        with open(cache_file, "w+") as file:
            contents[user.email] = asdict(user)
            file.write(json.dumps(contents, indent=2))

    def __get_api_key(self, req: requests.PreparedRequest) -> (str, str):
        config_file = os.path.join(self._config_dir, "projects.json")

        with open(config_file, "r") as file:
            config = json.load(file)

            project = req.headers.get("X-Firebase-Project") or self._project
            if project:
                return project, config["keys"][project]

            host = urlparse(req.url).netloc
            for endpoint in config["endpoints"]:
                project = endpoint["project"]

                if any(fnmatch.fnmatch(host, h) for h in endpoint["hosts"]):
                    logging.info("Found a match for project: [host=%s, project=%s]", host, project)
                    return project, config["keys"][project]

            project = config["default"]
            logging.warning("Falling back to default project:[host=%s, project=%s]", host, project)
            return project, config["keys"][project]

    def __refresh_token(self, api_key: str, user: Credential) -> Optional[Credential]:
        body = {
            "grant_type": "refresh_token",
            "refresh_token": user.refresh_token,
        }
        params = {
            "key": api_key,
        }

        resp = requests.post("https://securetoken.googleapis.com/v1/token", data=body, params=params)
        if resp.ok:
            data = resp.json()

            if data["project_id"] != self._project:
                logging.warning("Different project ID. got: %s, expected: %s", data["project_id"], self._project)

            if data["user_id"] != user.uid:
                logging.warning("Different UID. got: %s, expected: %s", data["user_id"], user.uid)

            return Credential(
                uid=user.uid,
                name=user.name,
                email=user.email,
                avatar=user.avatar,
                registered=user.registered,
                created=datetime.now().timestamp(),
                id_token=data["id_token"],
                refresh_token=data["refresh_token"],
                expires_in=data["expires_in"],
            )

    def __authenticate(self, api_key: str) -> Optional[Credential]:
        body = {
            "email": self._email,
            "password": self._password,
            "returnSecureToken": True,
        }
        params = {
            "key": api_key,
        }

        resp = requests.post(
            "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword",
            data=body,
            params=params,
        )
        if resp.ok:
            data = resp.json()
            return Credential(
                uid=data.get("localId"),
                name=data.get("displayName") or "",
                email=data.get("email"),
                avatar=data.get("profilePicture") or "",
                registered=data.get("registered"),
                id_token=data.get("idToken"),
                refresh_token=data.get("refreshToken"),
                expires_in=data.get("expiresIn"),
            )


class FirebaseAuthPlugin(AuthPlugin):
    name = "Firebase Auth"
    auth_type = "firebase"
    description = "Add Firebase JWT tokens to requests"
    auth_parse = False
    auth_require = False

    def __init__(self):
        pass

    def get_auth(self, username: str = None, password: str = None) -> FirebaseAuthenticator:
        parts = self.raw_auth.split(":")
        if not 2 <= len(parts) <= 3:
            raise "Invalid auth arguments provided"

        project = None
        if len(parts) == 3:
            project = parts[2]

        return FirebaseAuthenticator(parts[0] or username, parts[1] or password, project=project)
