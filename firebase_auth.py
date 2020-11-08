import json
import sys
import urllib
import os

import jwt

import requests
import firebase_admin
from httpie.config import get_default_config_dir
from httpie.core import main
from httpie.plugins import AuthPlugin
from requests import HTTPError

class FirebaseAuthPlugin(AuthPlugin):
    name = 'Firebase Auth'
    auth_type = 'firebase'
    description = 'Add Firebase JWT tokens to requests'

    def get_auth(self, username=None, password=None):
        parts = self.raw_auth.split(':')
        if not 2 <= len(parts) <= 3:
            raise 'Invalid auth arguments provided'

        project = None
        if len(parts) == 3:
            project = parts[2]

        return FirebaseAuth(username, password, project=project)


class FirebaseAuth:
    def __init__(self, email: str, password: str, project: str = None):
        self._email = email
        self._password = password
        self._project = project
        self._config_dir = os.path.join(get_default_config_dir(), '.auth')

    def __call__(self, req: requests.PreparedRequest) -> requests.PreparedRequest:
        host = urllib.parse.urlparse(req.url).netloc

        firebase = firebase_admin.initialize_app()

        config_file = os.path.join(self._config_dir, '%s.json' % host)
        user = None
        if os.path.isfile(config_file):
            with open(config_file, 'r') as file:
                json_user = file.read()
                if len(json_user):
                    user = json.loads(json_user)
                    try:
                        jwt.decode(user['idToken'], options={"verify_signature": False, 'verify_exp': True})
                    except jwt.ExpiredSignatureError:
                        sys.stderr.write(f'\n>>> Firebase: id token has expired, refreshing\n')
                        try:
                            user = firebase.auth().refresh(user['refreshToken'])
                            self.__write_user(config_file, user)
                        except HTTPError:
                            pass

        if not user:
            sys.stderr.write(f'\n>>> Firebase: authenticating user with email and password\n')
            user = firebase.auth().sign_in_with_email_and_password(self._email, self._password)
            self.__write_user(config_file, user)

        req.headers['Authorization'] = 'Bearer %s' % user['idToken']
        return req

    def __write_user(self, config_file, user):
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        with open(config_file, 'wt') as file:
            file.write(json.dumps(user, indent=2))


if __name__ == '__main__':
    # plugin_manager.register(FirebaseAuthPlugin())
    main()
