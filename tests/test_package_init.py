import sys
import os

PACKAGE_PARENT = '..{}src'.format(os.sep)
SCRIPT_DIR = os.path.dirname(os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(__file__))))
sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, PACKAGE_PARENT)))

import unittest
from pyjwt_wrapper import *
from pyjwt_wrapper.authentication import authenticate_using_user_credentials
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


class TestCreateHashFromDictionary(unittest.TestCase):

    def setUp(self):
        self.log_records = list()
        self.logger = Logger(logging_handler=ListHandler(records=self.log_records))
    
    def test_basic_working_test_01(self):
        d = { 'c': 1, 'a': 2, 'b': 3}
        salt = '1234567890'
        expected_result = 'd447bd72474f1f45abadf9ecf4b01e4ba77ee7757eeeea2a17287b15a7fb0420'
        result = create_hash_from_dictionary(
            d=d,
            logger=self.logger,
            salt=salt
        )
        self.assertEqual(result, expected_result)

    def test_invalid_input_parameter_01(self):
        test_parameters = [
            None,
            123,
            dict(),
            'some string',
            ''
        ]
        for d in test_parameters:
            exception_thrown = False
            try:
                result = create_hash_from_dictionary(
                    d=d,
                    logger=self.logger
                )
            except:
                exception_thrown = True
            self.assertTrue(exception_thrown, 'Failed to throw exception on parameter value "{}"'.format(d))


class TestDecodeJwtUnsafe(unittest.TestCase):

    def setUp(self):
        self.log_records = list()
        self.logger = Logger(logging_handler=ListHandler(records=self.log_records))

    def test_retrieval_of_token_data_01(self):
        username = 'user001'
        request_id = 'test_001'
        result = authenticate_using_user_credentials(
            application_name='test1',
            username=username,
            password='password',
            logger=self.logger,
            request_id=request_id
        )
        access_token = result['access_token']
        access_token_data = decode_jwt(
            jwt_data=result['access_token'],
            audience='test1',
        )
        access_token_checksum = create_hash_from_dictionary(
            d=access_token_data,
            logger=self.logger
        )
        unsafe_decoded_data = decode_jwt_unsafe(jwt_data=access_token)
        unsafe_decoded_data_checksum = create_hash_from_dictionary(
            d=unsafe_decoded_data,
            logger=self.logger
        )
        self.assertEqual(access_token_checksum, unsafe_decoded_data_checksum)
    

