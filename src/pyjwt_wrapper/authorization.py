import traceback
from pyjwt_wrapper import Logger, decode_jwt


default_logger = Logger()


def authorize_token(
    token: str, 
    application_name: str=None, 
    logger: Logger=default_logger, 
    request_id: str=None,
    required_permission: str=None
)->bool:
    authorized = False
    try:
        decoded_token = decode_jwt(jwt_data=token, audience=application_name)
        logger.info(message='Token validation passed', request_id=request_id)
        if required_permission:
            if 'prm' in decoded_token:
                if required_permission in decoded_token['prm']:
                    authorized = True
                else:
                    logger.error('Required permission "{}" not in list of user permissions.'.format(required_permission))
            else:
                logger.error('prm attribute not present in token')
        else:
            authorized = True
    except:
        logger.error(message='EXCEPTION: {}'.format(traceback.format_exc()), request_id=request_id)
    return authorized

