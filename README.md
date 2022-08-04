# HTTPie Firebase Auth Plugin

This project provides an authentication plugin for [HTTPie](https://httpie.io) that allows you to authenticate requests
using bearer tokens from [Firebase Auth](https://firebase.google.com/products/auth).

## Instalation

The plugin can be installed with PIP.

```bash
pip3 install --user httpie-firebase-auth
```

Once installed, you should see the option ``firebase`` under `--auth-type` in `http --help` output. The `--auth`
argument then accepts a username, password, and an optional project ID (`username:password[:project-id]`). If the
project ID is passed in the `auth` argument, it takes priority over the configuration file (outlined below).

```bash
# with username and password
https --auth-type=firebase -a user@gmail.com:p@ssw0rd api.example.com

# with username and password and project ID
https --auth-type=firebase -a user@gmail.com:p@ssw0rd:my-project-id api.example.com
```

## Configuration

There are several steps to perform before the plugin can add authentication details to HTTP requests.

### Projects

All project configuration happens in `${HTTPIE_CONFIG}/firebase/projects.json`. There is a section for `keys` that map a
project ID with an API key from the Firebase console. This key is the public web API key for the project.

**NOTE:** The project IDs do not need to match the project ID on Firebase.

### Endpoint mapping

The plugin allows HTTPie to determine the correct Firebase project to use to authenticate a given request. This means
that you can use different Firebase Auth projects for different endpoints. The endpoint section maps a project ID to a
list of hostname globs. There are two wildcard characters (`*` and `?`) for matching multiple characters or a single
character respectively. A default project can be specified as a fallback if none of the endpoints match.

### Example configuration file

```json
{
  "default": "project-1",
  "keys": {
    "project-1": "AIz....",
    "project-2": "AIz...."
  },
  "endpoints": [
    {
      "project": "project-1",
      "hosts": [
        "localhost",
        "api.example.com",
        "*.example.io"
      ]
    },
    {
      "project": "project-2",
      "hosts": [
        "prod.example.com"
      ]
    }
  ]
}
```

## Credential Caching

When a user is successfully authenticated against a Firebase project, the ID token and refresh token are cached in a
project specific file. On subsequent requests, if the provided email address is found in the project cache, the previous
ID token is used if it has not expired. If the token has expired, the refresh token is used to retrieve a new ID token.
The updated tokens are then stored in teh cache.

When combined with [HTTPie sessions](https://httpie.io/docs/cli/sessions), the plugin is able to
continue to authenticate requests for the user until the refresh token is no longer valid or revoked.

## TODO

- [ ] Document the `config.json`
    - [x] How to add a project to api-key mapping
    - [x] Structure for configuring which api-key/project is used for a set of hosts
    - [ ] Add more details to the config spec
    - [ ] Document credentials cache more completely
