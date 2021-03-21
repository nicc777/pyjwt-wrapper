An easy to use wrapper around [PyJWT](https://pyjwt.readthedocs.io/en/stable/index.html) for authentication and authorization.

- [Why this may be useful](#why-this-may-be-useful)
- [Quick Start](#quick-start)
  - [Installation](#installation)
  - [Implement your own `BackEndAuthenticator`](#implement-your-own-backendauthenticator)
  - [Authenticating a user that supplies a username and password](#authenticating-a-user-that-supplies-a-username-and-password)
  - [Authorize an API request using the `access_token` from Authentication](#authorize-an-api-request-using-the-access_token-from-authentication)
  - [Important Parameters](#important-parameters)
    - [Using the password salt](#using-the-password-salt)
    - [Using the JWT secret](#using-the-jwt-secret)
  - [Using the Refresh Token](#using-the-refresh-token)
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

# Quick Start

## Installation 

```shell
pip install pyjwt-wrapper
```

PyPi page: https://pypi.org/project/pyjwt-wrapper/ 

## Implement your own `BackEndAuthenticator`

Below is a quick example of how you would implement your own password based authentication. In stead of users being in a dictionary, you would typically connect to a database.

**_Note_**: The example below assumes the password is encoded using SHA256. However, when a user enters a password, we will receive it in normal text format which means it also needs to be SHA256 converted in order to compare to the password on record.

You would typically implement in this code in the application/API that handles authentication.

```python
from pyjwt_wrapper import Logger, BackEndAuthenticator, AuthenticationResult, generate_jwt, PASSWORD_SALT
import traceback
import hashlib


class MyBackEndAuthenticator(BackEndAuthenticator):
    def __init__(self, logger: Logger=Logger()):
        super().__init__(logger=logger)
    def authenticate(self, input: dict, request_id: str=None)->AuthenticationResult:
        my_hard_coded_users = {
            'user1': {
                'password': hashlib.sha256('!paSsWord123!{}'.format(PASSWORD_SALT).encode('utf-8')).hexdigest(),
                'permissions': ['p1', 'p2'],
                'active': True
            }
        }
        result = AuthenticationResult(
            success=False,
            userid=None,
            permissions=list()
        )
        try:
            input_password_hashed = hashlib.sha256('{}{}'.format(input['password'], PASSWORD_SALT).encode('utf-8')).hexdigest()
            if input['username'] in my_hard_coded_users:
                if my_hard_coded_users[input['username']]['active']:
                    if input_password_hashed == my_hard_coded_users[input['username']]['password']:
                        result.success = True
                        result.userid = input['username']
                        result.permissions = my_hard_coded_users[input['username']]['permissions']
                        self.logger.info(message='LOGIN SUCCESS for user "{}"'.format(input['username']), request_id=request_id)
                    else:
                        self.logger.error(message='LOGIN FAIL for user "{}" - incorrect password'.format(input['username']), request_id=request_id)
                else:
                    self.logger.error(message='LOGIN FAIL for user "{}" - user not active'.format(input['username']), request_id=request_id)
            else:
                self.logger.error(message='LOGIN FAIL for user "{}" - user not found'.format(input['username']), request_id=request_id)
        except:
            self.logger.error(message='EXCEPTION: {}'.format(traceback.format_exc()), request_id=request_id)
        return result
```

## Authenticating a user that supplies a username and password

You would also implement in this code in the application/API that handles authentication.

```python
from pyjwt_wrapper.authentication import  authenticate_using_user_credentials

# This part would tyically be implemented in a function that receives the username and password
result = authenticate_using_user_credentials(
    application_name='my_awesome_app',
    username='user1',
    password='!paSsWord123!',
    request_id='test123',
    backend=MyBackEndAuthenticator()
)

# Return the result to the client...
```

The result may look something like this:

```python
{
    'user_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteV9hd2Vzb21lX2FwcCIsInN1YiI6InVzZXIxIiwiY29udGV4dCI6Im15X2F3ZXNvbWVfYXBwIn0.qylm2cpukiUzCAjeDhO99iTMAWwdjuJKt4Jb2q0np2A', 
    'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteV9hd2Vzb21lX2FwcCIsInN1YiI6InVzZXIxIiwiYXVkIjoibXlfYXdlc29tZV9hcHAiLCJleHAiOjE2MTYzMTg1MTYsIm5iZiI6MTYxNjIzMjExNiwiaWF0IjoxNjE2MjMyMTE2LCJqdGkiOiJ0ZXN0MTIzIiwicHJtIjpbInAxIiwicDIiXX0.3UXG_fasgaj88ujbltHKqNUgJA1DJX9O6C6-i0Y1cIU', 
    'request_id': 'test123'
}
```

You should then use the `access_token` in every API call you make.

## Authorize an API request using the `access_token` from Authentication

The authorization code is implemented in applications/API that receives requests from the user, which is why each request must include the `access_token`.

```python
from pyjwt_wrapper.authorization import authorize_token

authorized = authorize_token(
    token=result['access_token'], 
    application_name='my_awesome_app',
    request_id='api123'
)
```

The resulting value from `authorized` should be `True`

## Important Parameters

There are two parameters that are important to take note of:

* `PASSWORD_SALT` - The salt used for added protection when storing passwords.
* `JWT_SECRET` - The secret required to encrypt and validate a JWT

### Using the password salt

Depending on your `BackEndAuthenticator` implementation, the `PASSWORD_SALT` may be considered optional. It's provided as a convenient way to include the parameter.

When your user register, your application should add some salt to ensure the password is even better protected when storing it in a database.

First, in the environment your application run, ensure the `PASSWORD_SALT` is set as an environment variable. This can be done using the following shell command on Linux like operating systems:

```shell
export PASSWORD_SALT="some really random text and special characters."
```

Typically, you will salt the password with something like:

```python
user_password = '....' # Store the user's password in a variable 
hashed_password = hashlib.sha256('{}{}'.format(user_password, PASSWORD_SALT).encode('utf-8')).hexdigest()

# You can now save the hashed_password in a database
```

If you want to generate a strong salt once-off, you can run the following shell command:

```shell
python3 -c "from pyjwt_wrapper import generate_random_string; print('{}'.format(generate_random_string(length=60)))"
```

**_Important_**: You need to safely and securely store your salt value as any password validation will be rendered useless if you don't have the original salt it was hashed with

### Using the JWT secret

The JWT secret is required and as with the password salt, you need to store it safely and securely. If you ever need to change the secret, any existing tokens created with the previous secret will not pass validation and all users would have to re-authenticate to get new tokens issued with the new secret.

Again, you can use the following one-liner utility to generate the secret:

```shell
python3 -c "from pyjwt_wrapper import generate_random_string; print('{}'.format(generate_random_string(length=60)))"
```

Set the following environment variable in your application environment:

```shell
export JWT_SECRET="some really random text and special characters."
```

## Using the Refresh Token

If your front-end application gets an authorization error and you have a refresh token, you need to use the refresh token to get another set of access and refresh tokens. 

Only once the refresh token have also reached expiry, must the application re-authenticate the user to get a fresh set of tokens. Form the front-end, this action can be triggered when both an API request and a refresh tokens request returned an error.

The refresh token by default only does the following basic checks in order to decide if the access token can be refreshed:

* Validate the supplied access token checksum is equal to the original calculated checksum
* Validate that the refresh token has not expired

If you need to do some additional validation, for example checking a back-end to see that the user account is still active, you can implement a function to do tat and pass it to the `refresh_tokens` function as a parameter. Here is an example:

```python
from pyjwt_wrapper.authentication import refresh_tokens
import traceback

def my_validation_function(*args)->bool:
    final_result = False # fail safely
    application_name = args[9]
    decoded_access_token = args[1]
    decoded_refresh_token = args[2]
    logger = args[3]
    request_id = args[4]
    secret_str = args[5]
    try:
        # Do your own checks here....
        pass
    except:
        logger.error(message='EXCEPTION: {}'.format(traceback.format_exc()), request_id=request_id)
    return final_result


# Later, call the refresh tokens function.
#
# In this example, if the validation function throws an exception, the default 
# behavior is changed to still force a success
#
# The access_token and _refresh_token is supplied by the calling client to your refresh API
refresh_tokens(
    application_name='your-great-app',
    access_token=access_token,
    refresh_token=refresh_token,
    request_id=request_id,
    user_validation_function=my_validation_function,
    default_user_validation_function_result_on_exception=True
)
```

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

* Create a customizable authorization class
* Create authorization caching feature
