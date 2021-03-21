import sys
import os

PACKAGE_PARENT = '..{}src'.format(os.sep)
SCRIPT_DIR = os.path.dirname(os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(__file__))))
sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, PACKAGE_PARENT)))

import unittest
from pyjwt_wrapper.authentication import authentication_service_default_response, authenticate_using_user_credentials, refresh_tokens
from pyjwt_wrapper import Logger, BackEndAuthenticator, AuthenticationResult, decode_jwt
from logging import Handler
import time


class ListHandler(Handler):
    """
        Ths is a logging handler specific geared for unit testing.
        
        All log messages are stored in a LIST which can be interrogated by the test framework
    """

    def __init__(self, records: list=list()):
        self.records = records
        super().__init__()

    def emit(self, record):
        self.records.append(record)


class AlwaysFailBackEndAuthenticator(BackEndAuthenticator):
    """
        This is an authentication backend that will always fail any loggin attempt
    """

    def __init__(self, logger: Logger=Logger()):
        super().__init__(logger=logger)

    def authenticate(self, input: dict, request_id: str=None)->AuthenticationResult:
        """
            This method will always fail an authentication request
        """
        self.logger.error(message='Authentication Attempt Failed for user "{}"... ALWAYS'.format(input['username']), request_id=request_id)
        return AuthenticationResult(
            success=False,
            userid=None,
            permissions=list()
        )


class AlwaysSucceedBackEndAuthenticatorWithExtras(BackEndAuthenticator):
    """
        This is an authentication backend that will always succeed any loggin attempt
    """

    def __init__(self, logger: Logger=Logger()):
        super().__init__(logger=logger)

    def authenticate(self, input: dict, request_id: str=None)->AuthenticationResult:
        """
            This method will always succeed an authentication request and add some extra data for both the access and user tokens
        """
        self.logger.error(message='Authentication Attempt Success for user "{}"... ALWAYS'.format(input['username']), request_id=request_id)
        result = AuthenticationResult(
            success=True,
            userid=input['username'],
            permissions=['p1', 'p2']
        )
        result.access_token_extra = {
            'attr1': 'value1',
            'attr2': True
        }
        result.user_token_extra = {
            'attr3': None,
            'attr4': 1234
        }
        return result


class TestAuthenticationServiceDefaultResponse(unittest.TestCase):

    def test_get_default_response(self):
        result = authentication_service_default_response()
        self.assertIsInstance(result, dict)
        self.assertTrue('user_token' in result)
        self.assertTrue('access_token' in result)
        self.assertTrue('refresh_token' in result)
        self.assertTrue('request_id' in result)
        self.assertIsNone(result['user_token'])
        self.assertIsNone(result['access_token'])
        self.assertIsNone(result['refresh_token'])
        self.assertIsNotNone(result['request_id'])
        self.assertIsInstance(result['request_id'], str)


class TestAuthenticationUsingUserCredentials(unittest.TestCase):

    def setUp(self):
        self.log_records = list()
        self.logger = Logger(logging_handler=ListHandler(records=self.log_records))

    def test_basic_01(self):
        username = 'user001'
        request_id = 'test_001'
        result = authenticate_using_user_credentials(
            application_name='test1',
            username=username,
            password='password',
            logger=self.logger,
            request_id=request_id
        )
        self.assertIsInstance(result, dict)
        self.assertTrue('user_token' in result)
        self.assertTrue('access_token' in result)
        self.assertTrue('request_id' in result)
        self.assertIsNotNone(result['user_token'])
        self.assertIsNotNone(result['access_token'])
        self.assertIsNotNone(result['request_id'])
        self.assertIsInstance(result['user_token'], str)
        self.assertIsInstance(result['access_token'], str)
        self.assertIsInstance(result['request_id'], str)
        self.assertTrue('USING A DEFAULT LOCAL INSTANCE - IMPLEMENT THIS CLASS YOURSELF TO CALL YOUR OWN BACKEND' in self.log_records[0].getMessage())
        self.assertTrue(username in self.log_records[1].getMessage())
        self.assertTrue(request_id in self.log_records[0].getMessage())
        self.assertTrue(request_id in self.log_records[1].getMessage())
        log_entry_validated = False
        for log_record in self.log_records:
            log_message = log_record.getMessage()
            if 'authenticated successfully' in log_message:
                log_entry_validated = True
            self.assertTrue(request_id in log_message, 'expected success message not in message: {}'.format(log_message))
        self.assertTrue(log_entry_validated)

    def test_authentication_failed_01(self):
        username = 'user002'
        request_id = 'test_002'
        result = authenticate_using_user_credentials(
            application_name='test2',
            username=username,
            password='password',
            logger=self.logger,
            request_id=request_id,
            backend=AlwaysFailBackEndAuthenticator(logger=self.logger)
        )
        self.assertIsInstance(result, dict)
        self.assertTrue('user_token' in result)
        self.assertTrue('access_token' in result)
        self.assertTrue('request_id' in result)
        self.assertIsNone(result['user_token'])
        self.assertIsNone(result['access_token'])
        self.assertIsNotNone(result['request_id'])
        self.assertIsInstance(result['request_id'], str)
        self.assertEqual(result['request_id'], request_id)
        fail_log_message = False
        for log_message in self.log_records:
            log_message_str = log_message.getMessage()
            if 'ALWAYS' in log_message_str and username in log_message_str:
                fail_log_message = True
        self.assertTrue(fail_log_message, 'Could not find failure log message')

    def test_authentication_success_with_extra_data_01(self):
        username = 'user003'
        request_id = 'test_003'
        result = authenticate_using_user_credentials(
            application_name='test3',
            username=username,
            password='password',
            logger=self.logger,
            request_id=request_id,
            backend=AlwaysSucceedBackEndAuthenticatorWithExtras(logger=self.logger)
        )
        self.assertIsInstance(result, dict)
        self.assertTrue('user_token' in result)
        self.assertTrue('access_token' in result)
        self.assertTrue('request_id' in result)
        self.assertIsNotNone(result['user_token'])
        self.assertIsNotNone(result['access_token'])
        self.assertIsNotNone(result['request_id'])
        self.assertIsInstance(result['user_token'], str)
        self.assertIsInstance(result['access_token'], str)
        self.assertIsInstance(result['request_id'], str)
        
        access_token_data = decode_jwt(result['access_token'], audience='test3')
        self.assertTrue('extra' in access_token_data)
        self.assertTrue('attr1' in access_token_data['extra'])
        self.assertTrue('attr2' in access_token_data['extra'])
        self.assertIsNotNone(access_token_data['extra']['attr1'])
        self.assertIsNotNone(access_token_data['extra']['attr2'])
        self.assertEqual(access_token_data['extra']['attr1'], 'value1')
        self.assertTrue(access_token_data['extra']['attr2'])

        user_token_data = decode_jwt(result['user_token'])
        self.assertTrue('extra' in user_token_data)
        self.assertTrue('attr3' in user_token_data['extra'])
        self.assertTrue('attr4' in user_token_data['extra'])
        self.assertIsNone(user_token_data['extra']['attr3'])
        self.assertIsNotNone(user_token_data['extra']['attr4'])
        self.assertEqual(user_token_data['extra']['attr4'], 1234)
        

class TestCreatingRefreshToken(unittest.TestCase):

    def setUp(self):
        self.log_records = list()
        self.logger = Logger(logging_handler=ListHandler(records=self.log_records))

    def test_basic_refresh_token__01(self):
        username = 'user001'
        request_id = 'test_001'
        result = authenticate_using_user_credentials(
            application_name='test1',
            username=username,
            password='password',
            logger=self.logger,
            request_id=request_id,
            include_refresh_token=True
        )
        self.assertTrue('refresh_token' in result)
        self.assertIsNotNone(result['refresh_token'])
        self.assertIsInstance(result['refresh_token'], str)
        self.assertTrue(len(result['refresh_token']) > 10)


def passing_user_validation_function(*args)->bool:
    return True


def failing_user_validation_function(*args)->bool:
    return False


class TestRefreshTokens(unittest.TestCase):

    def setUp(self):
        self.log_records = list()
        self.logger = Logger(logging_handler=ListHandler(records=self.log_records))

    def test_refresh_01(self):
        username = 'user001'
        request_id = 'test_001'
        tokens_1 = authenticate_using_user_credentials(
            application_name='test1',
            username=username,
            password='password',
            logger=self.logger,
            request_id=request_id,
            include_refresh_token=True
        )
        access_token_data_1 = decode_jwt(
            jwt_data=tokens_1['access_token'],
            audience='test1'
        )
        refresh_token_data_1 = decode_jwt(
            jwt_data=tokens_1['refresh_token']
        )
        time.sleep(3.0)
        tokens_2 = refresh_tokens(
            application_name='test1',
            access_token=tokens_1['access_token'],
            refresh_token=tokens_1['refresh_token'],
            logger=self.logger,
            request_id='test_002'
        )
        self.assertIsInstance(tokens_2, dict)
        self.assertTrue('user_token' in tokens_2)
        self.assertTrue('access_token' in tokens_2)
        self.assertTrue('refresh_token' in tokens_2)
        self.assertTrue('request_id' in tokens_2)
        self.assertIsNone(tokens_2['user_token'])
        self.assertIsNotNone(tokens_2['access_token'])
        self.assertIsNotNone(tokens_2['refresh_token'])
        self.assertIsNotNone(tokens_2['request_id'])
        self.assertIsInstance(tokens_2['access_token'], str)
        self.assertIsInstance(tokens_2['request_id'], str)
        self.assertEqual(tokens_2['request_id'], 'test_002')
        access_token_data_2 = decode_jwt(
            jwt_data=tokens_2['access_token'],
            audience='test1'
        )
        refresh_token_data_2 = decode_jwt(
            jwt_data=tokens_2['refresh_token']
        )
        self.assertIsInstance(access_token_data_2, dict)
        self.assertIsInstance(refresh_token_data_2, dict)
        self.assertTrue(
            access_token_data_2['exp'] > (access_token_data_1['exp'] + 2), 
            'exp_2={} vs exp_1={}   difference expected to be greater or equal than 600. Real difference: {}'.format(
                access_token_data_2['exp'],
                access_token_data_1['exp'],
                access_token_data_2['exp'] - access_token_data_1['exp']
            )
        )
        self.assertTrue(
            refresh_token_data_2['exp'] > (refresh_token_data_1['exp'] + 2), 
            'exp_2={} vs exp_1={}   difference expected to be greater or equal than 600. Real difference: {}'.format(
                refresh_token_data_2['exp'],
                refresh_token_data_1['exp'],
                refresh_token_data_2['exp'] - refresh_token_data_1['exp']
            )
        )

    def test_refresh_with_passing_user_validation_function_01(self):
        username = 'user001'
        request_id = 'test_003'
        tokens_1 = authenticate_using_user_credentials(
            application_name='test1',
            username=username,
            password='password',
            logger=self.logger,
            request_id=request_id,
            include_refresh_token=True
        )
        access_token_data_1 = decode_jwt(
            jwt_data=tokens_1['access_token'],
            audience='test1'
        )
        refresh_token_data_1 = decode_jwt(
            jwt_data=tokens_1['refresh_token']
        )
        tokens_2 = refresh_tokens(
            application_name='test1',
            access_token=tokens_1['access_token'],
            refresh_token=tokens_1['refresh_token'],
            logger=self.logger,
            request_id='test_004',
            user_validation_function=passing_user_validation_function
        )
        self.assertIsInstance(tokens_2, dict)
        self.assertTrue('user_token' in tokens_2)
        self.assertTrue('access_token' in tokens_2)
        self.assertTrue('refresh_token' in tokens_2)
        self.assertTrue('request_id' in tokens_2)
        self.assertIsNone(tokens_2['user_token'])
        self.assertIsNotNone(tokens_2['access_token'])
        self.assertIsNotNone(tokens_2['refresh_token'])
        self.assertIsNotNone(tokens_2['request_id'])
        self.assertIsInstance(tokens_2['access_token'], str)
        self.assertIsInstance(tokens_2['request_id'], str)
        self.assertEqual(tokens_2['request_id'], 'test_004')
        test_log_message = False
        for log_message in self.log_records:
            log_message_str = log_message.getMessage()
            if 'User validation function result: True' in log_message_str:
                test_log_message = True
        self.assertTrue(test_log_message, 'Could not find failure log message')

    def test_refresh_with_failing_user_validation_function_01(self):
        username = 'user001'
        request_id = 'test_005'
        tokens_1 = authenticate_using_user_credentials(
            application_name='test1',
            username=username,
            password='password',
            logger=self.logger,
            request_id=request_id,
            include_refresh_token=True
        )
        tokens_2 = refresh_tokens(
            application_name='test1',
            access_token=tokens_1['access_token'],
            refresh_token=tokens_1['refresh_token'],
            logger=self.logger,
            request_id='test_006',
            user_validation_function=failing_user_validation_function
        )
        self.assertIsInstance(tokens_2, dict)
        self.assertTrue('user_token' in tokens_2)
        self.assertTrue('access_token' in tokens_2)
        self.assertTrue('refresh_token' in tokens_2)
        self.assertTrue('request_id' in tokens_2)
        self.assertIsNone(tokens_2['user_token'])
        self.assertIsNone(tokens_2['access_token'])
        self.assertIsNone(tokens_2['refresh_token'])
        self.assertIsNotNone(tokens_2['request_id'])
        self.assertIsInstance(tokens_2['request_id'], str)
        self.assertEqual(tokens_2['request_id'], 'test_006')
        test_log_message = False
        for log_message in self.log_records:
            log_message_str = log_message.getMessage()
            if 'User validation function result: False' in log_message_str:
                test_log_message = True
        self.assertTrue(test_log_message, 'Could not find failure log message')

    def test_refresh_token_expired_01(self):
        username = 'user001'
        request_id = 'test_007'
        tokens_1 = authenticate_using_user_credentials(
            application_name='test1',
            username=username,
            password='password',
            logger=self.logger,
            request_id=request_id,
            include_refresh_token=True,
            refresh_token_ttl=1
        )
        time.sleep(2)
        tokens_2 = refresh_tokens(
            application_name='test1',
            access_token=tokens_1['access_token'],
            refresh_token=tokens_1['refresh_token'],
            logger=self.logger,
            request_id='test_008',
            user_validation_function=failing_user_validation_function
        )
        self.assertIsInstance(tokens_2, dict)
        self.assertTrue('user_token' in tokens_2)
        self.assertTrue('access_token' in tokens_2)
        self.assertTrue('refresh_token' in tokens_2)
        self.assertTrue('request_id' in tokens_2)
        self.assertIsNone(tokens_2['user_token'])
        self.assertIsNone(tokens_2['access_token'])
        self.assertIsNone(tokens_2['refresh_token'])
        self.assertIsNotNone(tokens_2['request_id'])
        self.assertIsInstance(tokens_2['request_id'], str)
        self.assertEqual(tokens_2['request_id'], 'test_008')


if __name__ == '__main__':
    unittest.main()
