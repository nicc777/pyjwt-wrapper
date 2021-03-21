from pyjwt_wrapper import Logger, BackEndAuthenticator, generate_jwt, get_utc_timestamp, JWT_SECRET, PASSWORD_SALT, create_hash_from_dictionary
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
    request_id: str=None,
    logger: Logger=Logger()
)->dict:
    refresh_token_data = dict()
    if len(access_token_data) > 0:
        now = get_utc_timestamp(with_decimal=False)
        access_token_data_json_hash = create_hash_from_dictionary(d=access_token_data, logger=logger, salt=salt)
        refresh_token_data['ath'] = access_token_data_json_hash
        refresh_token_data['exp'] = int(now + refresh_token_ttl)
    return refresh_token_data


def create_access_token_data(
    application_name: str,
    username: str,
    token_expires_in_seconds: int,
    permissions: list,
    request_id: str=None
)->str:
    now = get_utc_timestamp(with_decimal=False)
    access_token_data = {
        'iss': application_name,
        'sub': '{}'.format(username),
        'aud': '{}'.format(application_name),
        'exp': int(now + token_expires_in_seconds),
        'nbf': int(now),
        'iat': int(now),
        'jti': request_id,
        'prm': permissions
    }
    return access_token_data


def create_final_result_with_tokens(
    access_token_data: dict,
    user_token_data: dict=dict(),
    refresh_token_data: dict=dict(),
    secret_str: str=JWT_SECRET,
    logger: Logger=default_logger,
    request_id: str=None
)->dict:
    result = authentication_service_default_response()
    result['request_id'] = request_id
    try:
        username = None
        if len(access_token_data) > 0:
            result['access_token'] = generate_jwt(data=access_token_data, secret_str=secret_str)
            username = access_token_data['sub']
            logger.info(message='access token for user "{}" created'.format(username), request_id=request_id)
        if len(user_token_data) > 0:
            result['user_token'] = generate_jwt(data=user_token_data, secret_str=secret_str)
            logger.info(message='user token for user "{}" created'.format(username), request_id=request_id)
        if len(refresh_token_data) > 0:
            result['refresh_token'] = generate_jwt(data=refresh_token_data, secret_str=secret_str)
            logger.info(message='refresh token for user "{}" created'.format(username), request_id=request_id)
        logger.debug(message='access_token: {}'.format(result['access_token']), request_id=request_id)
        logger.debug(message='user_token: {}'.format(result['user_token']), request_id=request_id)
        logger.debug(message='refresh_token: {}'.format(result['refresh_token']), request_id=request_id)
    except:
        logger.error(message='EXCEPTION: {}'.format(traceback.format_exc()), request_id=request_id)
    return result


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
    authentication_backend_call_result = backend.authenticate(
        input={
            'username': username,
            'password': password
        },
        request_id=request_id
    )
    result = dict()
    if authentication_backend_call_result.success:
        access_token_data = create_access_token_data(
            application_name=application_name,
            username=username,
            token_expires_in_seconds=token_expires_in_seconds,
            permissions=authentication_backend_call_result.permissions,
            request_id=request_id
        )
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
        result = create_final_result_with_tokens(
            access_token_data=access_token_data,
            user_token_data=user_token_data,
            refresh_token_data=refresh_token_data,
            secret_str=secret_str,
            logger=logger,
            request_id=request_id
        )
        if result['access_token']:
            if len(result['access_token']) > 0:
                logger.info(message='user "{}" authenticated successfully'.format(username), request_id=request_id)
            else:
                logger.error(message='user"{}" authenticated but access_token was not created. [1]', request_id=request_id)
        else:
            logger.error(message='user"{}" authenticated but access_token was not created. [2]', request_id=request_id)
    else:
         logger.error(message='user "{}" authenticated FAILED'.format(username), request_id=request_id)
         result = authentication_service_default_response()
         result['request_id'] = request_id
    return result