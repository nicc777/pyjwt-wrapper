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

    def test_permissions_not_required_01(self):
        username = 'user001'
        request_id = 'test_003'
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
            request_id=request_id
        )
        self.assertTrue(authorized)
        log_entry_validated = False
        for log_record in self.log_records:
            log_message = log_record.getMessage()
            if 'AUTHORIZED [03]' in log_message:
                log_entry_validated = True
            self.assertTrue(request_id in log_message, 'request_id not present in message: {}'.format(log_message))
        self.assertTrue(log_entry_validated)

    def test_malformed_token_raises_exception(self):
        request_id = 'test_004'
        authorized = authorize_token(
            token='aaa.bbb.ccc', 
            application_name='test1', 
            logger=self.logger, 
            request_id=request_id
        )
        self.assertFalse(authorized)
        log_entry_validated = False
        for log_record in self.log_records:
            log_message = log_record.getMessage()
            if 'EXCEPTION' in log_message:
                log_entry_validated = True
            self.assertTrue(request_id in log_message, 'request_id not present in message: {}'.format(log_message))
        self.assertTrue(log_entry_validated)

    def test_fail_fraudelant_token(self):
        request_id = 'test_005'
        authorized = authorize_token(
            token='eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0Iiwic3ViIjoidXNlcjEiLCJhdWQiOiJ0ZXN0IiwiZXhwIjoxNjE2MTM2NjIwLCJuYmYiOjE2MTYwNTAyMjAsImlhdCI6MTYxNjA1MDIyMCwianRpIjpudWxsLCJwcm0iOlsiYWRtaW4iXX0.FHjyjnDBSG_F8sVycPRP8iJpsD83ZZNw_UOiPobXI0U', 
            application_name='test1', 
            logger=self.logger, 
            request_id=request_id
        )
        self.assertFalse(authorized)
        log_entry_validated = False
        for log_record in self.log_records:
            log_message = log_record.getMessage()
            if 'EXCEPTION' in log_message:
                log_entry_validated = True
            self.assertTrue(request_id in log_message, 'request_id not present in message: {}'.format(log_message))
        self.assertTrue(log_entry_validated)

    def test_success_based_on_passed_in_secret_01(self):
        secret = 'abcdefghijklmnopqrstuvwxyz'
        username = 'user001'
        request_id = 'test_003'
        result = authenticate_using_user_credentials(
            application_name='test1',
            username=username,
            password='password',
            logger=self.logger,
            request_id=request_id,
            secret_str= secret
        )
        authorized = authorize_token(
            token=result['access_token'], 
            application_name='test1', 
            logger=self.logger, 
            request_id=request_id,
            secret_str= secret
        )
        self.assertTrue(authorized)

    def test_fail_based_on_passed_in_secret_that_differ_01(self):
        secret1 = 'abcdefghijklmnopqrstuvwxyz'
        secret2 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        username = 'user001'
        request_id = 'test_003'
        result = authenticate_using_user_credentials(
            application_name='test1',
            username=username,
            password='password',
            logger=self.logger,
            request_id=request_id,
            secret_str= secret1
        )
        authorized = authorize_token(
            token=result['access_token'], 
            application_name='test1', 
            logger=self.logger, 
            request_id=request_id,
            secret_str= secret2
        )
        self.assertFalse(authorized)
