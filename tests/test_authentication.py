import sys
import os

PACKAGE_PARENT = '..{}src'.format(os.sep)
SCRIPT_DIR = os.path.dirname(os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(__file__))))
sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, PACKAGE_PARENT)))

import unittest
from pyjwt_wrapper.authentication import authentication_service_default_response, authenticate_using_user_credentials
from pyjwt_wrapper import Logger
from logging import Handler


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


class TestAuthenticationServiceDefaultResponse(unittest.TestCase):

    def test_get_default_response(self):
        result = authentication_service_default_response()
        self.assertIsInstance(result, dict)
        self.assertTrue('user_token' in result)
        self.assertTrue('access_token' in result)
        self.assertTrue('request_id' in result)
        self.assertIsNone(result['user_token'])
        self.assertIsNone(result['access_token'])
        self.assertIsNotNone(result['request_id'])
        self.assertIsInstance(result['request_id'], str)


class TestAuthenticationUsingUserCredentials(unittest.TestCase):

    def setUp(self):
        self.log_records = list()
        self.logger = Logger(logging_handler=ListHandler(records=self.log_records))

    def test_basic_01(self):
        username = 'user123'
        request_id = 'test_001'
        result = authenticate_using_user_credentials(
            application_name='test',
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
        self.assertTrue('authenticated successfully' in self.log_records[1].getMessage())
        self.assertTrue(request_id in self.log_records[0].getMessage())
        self.assertTrue(request_id in self.log_records[1].getMessage())

    

if __name__ == '__main__':
    unittest.main()
