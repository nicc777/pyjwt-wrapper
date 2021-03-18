import traceback
from pyjwt_wrapper import Logger, decode_jwt, JWT_SECRET


default_logger = Logger()


def authorize_token(
    token: str, 
    application_name: str=None, 
    logger: Logger=default_logger, 
    request_id: str=None,
    required_permission: str=None,
    secret_str: str=JWT_SECRET
)->bool:
    authorized = False
    try:
        decoded_token = decode_jwt(jwt_data=token, audience=application_name, secret_str=secret_str)
        logger.info(message='Token validation passed', request_id=request_id)
        if required_permission:
            if 'prm' in decoded_token:
                if required_permission in decoded_token['prm']:
                    logger.info('AUTHORIZED [01]', request_id=request_id)
                    authorized = True
                else:
                    logger.error('Required permission "{}" not in list of user permissions.'.format(required_permission), request_id=request_id)
            else:   # This should never happen. Logging the event anyway as this may be an indication of some malicious intent
                logger.error(message='prm attribute not present', request_id=request_id)    # pragma: no cover
        else:
            logger.info('AUTHORIZED [03]', request_id=request_id)
            authorized = True
    except:
        logger.error(message='EXCEPTION: {}'.format(traceback.format_exc()), request_id=request_id)
    return authorized

