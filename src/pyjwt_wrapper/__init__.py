import inspect
import os
from datetime import datetime
import logging
import hashlib
import jwt
import random


def generate_random_string(length: int=20):
    chars = 'abcdefghijklmnopqrstuvwxyx1234567890!@#$%^&*()":?><,./;[]-=_+ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    result = ''
    while len(result) < length:
        result = '{}{}'.format(result, random.choice(chars))
    return result


PASSWORD_SALT = os.getenv('PASSWORD_SALT', generate_random_string(length=40))
JWT_SECRET = os.getenv('JWT_SECRET', generate_random_string(length=60))


def get_default_logger():
    logger = logging.getLogger('pyjwt-wrapper')
    logger.setLevel(logging.INFO)
    if os.getenv('DEBUG', None):
        logger.setLevel(logging.DEBUG)
    return logger


def get_default_log_handler():
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    if os.getenv('DEBUG', None):
        ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    return ch


def get_utc_timestamp(with_decimal: bool=False):
    epoch = datetime(1970,1,1,0,0,0)
    now = datetime.utcnow()
    timestamp = (now - epoch).total_seconds()
    if with_decimal:
        return timestamp
    return int(timestamp)


def id_caller()->list:
    result = list()
    try:
        caller_stack = inspect.stack()[2]
        result.append(caller_stack[1].split(os.sep)[-1]) # File name
        result.append(caller_stack[2]) # line number
        result.append(caller_stack[3]) # function name
    except: # pragma: no cover
        pass
    return result


class Logger:
    def __init__(self, logger=get_default_logger() ,logging_handler=get_default_log_handler()):
        logger.addHandler(logging_handler)
        self.logger = logger

    def _format_msg(self, stack_data: list, message: str, request_id: str=None)->str:
        if message is not None:
            message = '{}'.format(message)
            if len(stack_data) == 3:
                message = '[{}:{}:{}] {}'.format(
                    stack_data[0],
                    stack_data[1],
                    stack_data[2],
                    message
                )
            if request_id:
                message = '[{}] {}'.format(
                    request_id,
                    message
                )
            return message
        return 'NO_INPUT_MESSAGE'

    def info(self, message: str, request_id: str=None):
        self.logger.info(
            self._format_msg(
                stack_data=id_caller(), 
                message=message, 
                request_id=request_id
            )
        )

    def warning(self, message: str, request_id: str=None):
        self.logger.warning(
            self._format_msg(
                stack_data=id_caller(), 
                message=message, 
                request_id=request_id
            )
        )

    def error(self, message: str, request_id: str=None):
        self.logger.error(
            self._format_msg(
                stack_data=id_caller(), 
                message=message, 
                request_id=request_id
            )
        )

    def debug(self, message: str, request_id: str=None):
        self.logger.debug(
            self._format_msg(
                stack_data=id_caller(), 
                message=message, 
                request_id=request_id
            )
        )


class AuthenticationResult:

    def __init__(
        self,
        success: bool=False,
        userid: str=None,
        permissions: list=list()
    ):
        self.success = success
        self.userid = userid
        self.permissions = permissions
        self.access_token_extra = dict()
        self.user_token_extra = dict()
    
    def to_dict(self):
        result = dict()
        result['success'] = self.success
        result['userid'] = self.userid
        result['permissions'] = self.permissions
        if len(self.access_token_extra) > 0:
            result['access_token_extra'] = self.access_token_extra
        if len(self.user_token_extra) > 0:
            result['user_token_extra'] = self.user_token_extra
        return result


class BackEndAuthenticator:

    def __init__(self, logger: Logger=Logger()):
        self.logger = logger

    def authenticate(self, input: dict, request_id: str=None)->AuthenticationResult:
        """
        This method takes a dictionary as input and the dictionary could contain any number of arguments you require for your backend.

        Typical examples may include a 'username' and 'password' keys for the input

        An optional request_id parameter of type string can be passed which you can use in log messages.

        The result is a standard response class AuthenticationResult
        """
        self.logger.warning(message='USING A DEFAULT LOCAL INSTANCE - IMPLEMENT THIS CLASS YOURSELF TO CALL YOUR OWN BACKEND', request_id=request_id)
        return AuthenticationResult(
            success=True,
            userid=1,
            permissions=['admin']
        )




def password_hash(password: str, salt: str=PASSWORD_SALT)->str:
    final_str = '{}{}'.format(password, salt)
    return hashlib.sha256(final_str.encode('utf-8')).hexdigest()


def generate_jwt(data: dict, secret_str: str=JWT_SECRET):
    return jwt.encode(data, secret_str, algorithm="HS256")


def decode_jwt(jwt_data: str, audience: str=None, secret_str: str=JWT_SECRET)->dict:
    if audience:
        return jwt.decode(jwt_data, secret_str, audience=audience, algorithms="HS256")
    return jwt.decode(jwt_data, secret_str, algorithms="HS256")


def decode_jwt_unsafe(jwt_data: str)->dict:
    return jwt.decode(jwt_data, options={"verify_signature": False})


def create_hash_from_dictionary(d: dict, logger: Logger=Logger(), salt: str=PASSWORD_SALT)->str:
    result = None
    if d is None:
        raise Exception('Dictionary value cannot be None')
    if not isinstance(d, dict):
        raise Exception('Parameter must be of type dict')
    if len(d) < 1:
        raise Exception('Parameter must have at least one value')
    try:
        d_keys = list(d.keys())
        d_keys.sort()
        data = ''
        for k in d_keys:
            v = '{}'.format(d[k])
            data = '{}|{}={}'.format(data, k, v)
        result = hashlib.sha256('{}{}'.format(data, salt).encode('utf-8')).hexdigest()
    except:
        logger.error(message='EXCEPTION: {}'.format(traceback.format_exc()), request_id=request_id)
    if result is None:
        raise Exception('Failed to create hash - result was None')
    if not isinstance(result, str):
        raise Exception('Failed to create hash - result was not a string')
    if len(result) < 10:
        raise Exception('Failed to create hash - resulting string is not long enough')
    return result


# EOF
