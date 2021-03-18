import sys
import os

PACKAGE_PARENT = '..{}src'.format(os.sep)
SCRIPT_DIR = os.path.dirname(os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(__file__))))
sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, PACKAGE_PARENT)))

import unittest
from pyjwt_wrapper.authorization import authorize_token
from pyjwt_wrapper.authentication import authenticate_using_user_credentials
from pyjwt_wrapper import Logger, AuthenticationResult, decode_jwt, BackEndAuthenticator
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


class TestAuthorization(unittest.TestCase):

    def setUp(self):
        self.log_records = list()
        self.logger = Logger(logging_handler=ListHandler(records=self.log_records))

    def test_basic_authorization_01(self):
        username = 'user001'
        request_id = 'test_001'
        result = authenticate_using_user_credentials(
            application_name='test1',
            username=username,
            password='password',
            logger=self.logger,
            request_id=request_id
        )
        authorized = authorize_token(
            token=result['access_token'], 
            application_name='test1', 
            logger=self.logger, 
            request_id=request_id,
            required_permission='admin'
        )
        self.assertTrue(authorized)
        log_entry_validated = False
        for log_record in self.log_records:
            log_message = log_record.getMessage()
            if 'AUTHORIZED [01]' in log_message:
                log_entry_validated = True
            self.assertTrue(request_id in log_message, 'request_id not present in message: {}'.format(log_message))
        self.assertTrue(log_entry_validated)

    def test_permission_not_in_list_01(self):
        username = 'user001'
        request_id = 'test_002'
        result = authenticate_using_user_credentials(
            application_name='test1',
            username=username,
            password='password',
            logger=self.logger,
            request_id=request_id
        )
        authorized = authorize_token(
            token=result['access_token'], 
            application_name='test1', 
            logger=self.logger, 
            request_id=request_id,
            required_permission='user'
        )
        self.assertFalse(authorized)
        log_entry_validated = False
        for log_record in self.log_records:
            log_message = log_record.getMessage()
            if 'Required permission "user" not in list of user permissions.' in log_message:
                log_entry_validated = True
            self.assertTrue(request_id in log_message, 'request_id not present in message: {}'.format(log_message))
        self.assertTrue(log_entry_validated)
