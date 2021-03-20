from pyjwt_wrapper import Logger, BackEndAuthenticator, generate_jwt, get_utc_timestamp, JWT_SECRET, PASSWORD_SALT
import json
import traceback
import hashlib


default_logger = Logger()


def authentication_service_default_response()->dict:
    return {
        'user_token': None,
        'access_token': None,
        'refresh_token': None,
        'request_id': ''
    }


def create_refresh_token(
    access_token_data: dict,
    salt: str=PASSWORD_SALT,
    refresh_token_ttl: int=86400,
    request_id: str=None
)->dict:
    refresh_token_data = dict()
    if len(access_token_data) > 0:
        now = get_utc_timestamp(with_decimal=False)
        access_token_data_json = json.dumps(access_token_data)
        access_token_data_json_hash = hashlib.sha256('{}{}'.format(access_token_data_json, PASSWORD_SALT).encode('utf-8')).hexdigest()
        refresh_token_data['ath'] = access_token_data_json_hash
        refresh_token_data['exp'] = int(now + refresh_token_ttl)
    return refresh_token_data


def authenticate_using_user_credentials(
    application_name: str,
    username: str,
    password: str,
    logger: Logger=default_logger,
    backend: BackEndAuthenticator=BackEndAuthenticator(logger=default_logger),
    request_id: str=None,
    token_expires_in_seconds: int=600,
    convert_username_to_lowercase: bool=True,
    secret_str: str=JWT_SECRET,
    include_refresh_token: bool=False,
    refresh_token_salt: str=PASSWORD_SALT,
    refresh_token_ttl: int=86400
)->dict:
    if convert_username_to_lowercase:
        username = username.lower()
    result = authentication_service_default_response()
    result['request_id'] = request_id
    authentication_backend_call_result = backend.authenticate(
        input={
            'username': username,
            'password': password
        },
        request_id=request_id
    )
    if authentication_backend_call_result.success:
        now = get_utc_timestamp(with_decimal=False)
        access_token_data = {
            'iss': application_name,
            'sub': '{}'.format(username),
            'aud': '{}'.format(application_name),
            'exp': int(now + token_expires_in_seconds),
            'nbf': int(now),
            'iat': int(now),
            'jti': request_id,
            'prm': authentication_backend_call_result.permissions
        }
        user_token_data = {
            'iss': application_name,
            'sub': '{}'.format(username),
            'context': '{}'.format(application_name),
        }
        refresh_token_data = dict()
        if include_refresh_token:
            try:
                refresh_token_data = create_refresh_token(
                    access_token_data=access_token_data,
                    salt=refresh_token_salt,
                    request_id=request_id
                )
            except:
                logger.error(message='EXCEPTION: {}'.format(traceback.format_exc()), request_id=request_id)
        if len(authentication_backend_call_result.access_token_extra) > 0:
            access_token_data['extra'] = authentication_backend_call_result.access_token_extra
        if len(authentication_backend_call_result.user_token_extra) > 0:
            user_token_data['extra'] = authentication_backend_call_result.user_token_extra
        result['access_token'] = generate_jwt(data=access_token_data, secret_str=secret_str)
        result['user_token'] = generate_jwt(data=user_token_data, secret_str=secret_str)
        if include_refresh_token and len(refresh_token_data) > 0:
            result['refresh_token'] = generate_jwt(data=refresh_token_data, secret_str=secret_str)
        logger.info(message='user "{}" authenticated successfully'.format(username), request_id=request_id)
        logger.debug(message='access_token: {}'.format(result['access_token']), request_id=request_id)
        logger.debug(message='user_token: {}'.format(result['user_token']), request_id=request_id)
    else:
         logger.error(message='user "{}" authenticated FAILED'.format(username), request_id=request_id)
    return result