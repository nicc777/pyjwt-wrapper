An easy to use wrapper around [PyJWT](https://pyjwt.readthedocs.io/en/stable/index.html) for authentication and authorization.

- [Why this may be useful](#why-this-may-be-useful)
- [Implementation](#implementation)
  - [Authentication](#authentication)
  - [The JSON Web Token (generated from `pyjwt_wrapper.authentication`)](#the-json-web-token-generated-from-pyjwt_wrapperauthentication)
    - [Access Token](#access-token)
    - [User Token](#user-token)
  - [Authorization (as implemented by from `pyjwt_wrapper.authorization`)](#authorization-as-implemented-by-from-pyjwt_wrapperauthorization)
  - [Logging](#logging)
- [Testing from Source](#testing-from-source)
- [To Do](#to-do)

**_Note_**: The development is still in an early stage, and therefore documentation should improve over time. Right now, only some basic concepts are covered.

# Why this may be useful

PyJWT is a really solid library and a very useful tool for creating and using JSON Web tokens (JWT) in applications. Check out https://jwt.io/ for more info around JSON Web Tokens.

This library is a wrapper around PyJWT that creates a standard `access token` and `user token`.

**_Note_**: Refresh tokens to come soon...

# Implementation

This library can be used in two different contexts:

1. During user authentication which will result in a `access_token` and `user_token` being issues
2. During API requests, where a previously issued `access_token` is validated and some tests are done before the request is authorized.

For the authentication portion, you will probably implement this library at the authentication API end-point.

For authorization, you would typically implement this library in your API Gateway or proxy server in the authorization leg.

## Authentication

You will still need to implement the actual method of authentication. This process is facilitated by the `BackEndAuthenticator` class which you need to extend with your own implementation of the `authenticate` method.

The `authenticate` method returns a `AuthenticationResult` which contains enough information to finally construct the dictionary that will hold the `access token` and `user token`.

## The JSON Web Token (generated from `pyjwt_wrapper.authentication`)

Thus far, this library only support `username` and `password` authentication in a function called `authenticate_using_user_credentials` (name may change in future).

### Access Token

The access token is typically used by one application that is requesting resources from another application to authorize the first application. The authorization is usually done by some kind of a proxy in front of the second application. A web page rendered in a user's web browser that requests some data from an application hosted on the Internet is a typical example of this setup. In this case the web page will include the `access_token` with each request to the application API. Each request has to pass the authorization check before the application will respond with the requested data.

There are a number of resources on the Internet that will explain in a lot more detail the mechanics of authorization, but Auth0 has a very good [lightweight explanation](https://auth0.com/docs/tokens/json-web-tokens/validate-json-web-tokens) of how the process would work.

The `access_token` contains the following elements:

* `iss` - The [issuer claim](https://tools.ietf.org/html/rfc7519#section-4.1.1) which is the value of the `application_name` parameter. In web applications you could derive this from the `Host` header.
* `sub` - The [subject claim](https://tools.ietf.org/html/rfc7519#section-4.1.2) is currently mapped to the `username` in username/passwords authentication
* `aud` - The [audience claim](https://tools.ietf.org/html/rfc7519#section-4.1.3) which is also mapped to the `application_name` parameter at the moment.
* `exp` - The [expiration time claim](https://tools.ietf.org/html/rfc7519#section-4.1.4) which is the Unix timestamp (UTC) after which this token is no longer considered valid.
* `nbf` - The [not before claim](https://tools.ietf.org/html/rfc7519#section-4.1.5) which is set to the Unix timestamp (UTC) of token creation
* `iat` - The [issued at claim](https://tools.ietf.org/html/rfc7519#section-4.1.6) which is set to the Unix timestamp (UTC) of token creation
* `jti` - The [JWT ID claim](https://tools.ietf.org/html/rfc7519#section-4.1.7) which is mapped to the `request_id` parameter
* `prm` - A list of permission names (strings) that was valid for the user at the time of authentication. This may be useful in some front-end application to decide which components to render. For example, only provide administrator controls/components to the users that have admin rights.
* `extra` - An optional parameter that will only be present if the `BackEndAuthenticator` included extra data to include in the token. This is a standard dictionary and should only contain primitives.

### User Token

The user token (also known as the ID token) contains basic user profile information. 

The `access_token` contains the following elements:

* `iss` - The [issuer claim](https://tools.ietf.org/html/rfc7519#section-4.1.1) which is the value of the `application_name` parameter. In web applications you could derive this from the `Host` header.
* `sub` - The [subject claim](https://tools.ietf.org/html/rfc7519#section-4.1.2) is currently mapped to the `username` in username/passwords authentication
* `context` - This value is from the `application_name` parameter.
* `extra` - An optional parameter that will only be present if the `BackEndAuthenticator` included extra data to include in the token. This is a standard dictionary and should only contain primitives.

## Authorization (as implemented by from `pyjwt_wrapper.authorization`)

During the authorization phase, PyJWT is used for the general token validation.

In addition, the `authorize_token` takes a number of other parameters used in the authorization process:

* `application_name`, which will be used to validate the `aud` claim
* `required_permission` which is a parameter you pass in based on the type of request. The function will test if this value is present in the `prm` claim values.

## Logging

The library utilizes the standard [Python logging framework](https://docs.python.org/3/library/logging.html) and by default will use a STDOUT log handler.

Most functions takes a `logger` parameter which implements the `Logger` class. If you create your own [handler](https://docs.python.org/3/howto/logging.html#useful-handlers), just create it yourself and initialize `Logger` with your handler. 

Example:

```python
from pyjwt_wrapper import Logger
import logging

fh = logging.FileHandler('spam.log')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

my_logger = Logger(logging_handler=fh)

# later usage...
from pyjwt_wrapper.authentication import authenticate_using_user_credentials

auth_result = authenticate_using_user_credentials(
    application_name='my_aoo',
    username='some_user@example.tld',
    password='the world strongest password',
    logger=my_logger,
)

# Use the logger in your own app:
my_logger.info(message='This is a test', request_id='some-request-reference...')
```

# Testing from Source

Basic steps:

1. Clone the repository
2. Create a Python Virtual Environment
3. Install dependencies
4. Run the unit tests
5. Get teh coverage reports

The steps above can all be summarized in the following list of Unix commands (bash or zsh):

```shell
# Clone the repository
git clone https://github.com/nicc777/pyjwt-wrapper.git

cd pyjwt-wrapper

# Create a Python Virtual Environment
python -m venv venv

. venv/bin/activate

# Install dependencies
pip install pyjwt coverage

# Run the unit tests
coverage run --source ./src -m unittest discover

# Get teh coverage reports
coverage report -m
```

# To Do

* Creation of Refresh Tokens
* Managing of Refresh Tokens
