from nio.signal.base import Signal
from nio.testing.block_test_case import NIOBlockTestCase
from ..jwt_validate_block import JWTValidate
import jwt
import datetime

class TestJWTValidate(NIOBlockTestCase):

    def test_validate_token_with_passing_expiration(self):
        config = {
          'key': 'secret',
          'algorithm': 'HS256',
          'validate_expiration': True,
          'input': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1ODIzMjg0OTIsInVzZXJfaWQiOiI1YzZkZDdjNjJjMWZlZGE3NTI0MzEyNmMifQ.tlrHNvcrki94CzkLyZSXKlBDI2skWhNOJsQ0Sh4fB_I'  # expires 02.21.20      
        }

        blk = JWTValidate()
        blk.start()
        self.configure_block(blk, config)
        blk.process_signals([{}])
        self.assert_num_signals_notified(1, blk)
        self.assertEqual('Token is valid', self.last_signal_notified().message)
        self.assertEqual(0, self.last_signal_notified().error)
        self.assertIsNotNone(self.last_signal_notified().token)
        self.assertEqual(type(self.last_signal_notified().token), str)
        self.assertEqual(jwt.decode(self.last_signal_notified().token, 'secret', algorithms=['HS256']), {'exp': 1582328492, 'user_id': '5c6dd7c62c1feda75243126c'})
        blk.stop()

    def test_validate_token_with_failing_expiration(self):
        config = {
          'key': 'secret',
          'algorithm': 'HS256',
          'validate_expiration': True,
          'input': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1NTA3OTI2NDEsInVzZXJfaWQiOiI1YzZkZDdjNjJjMWZlZGE3NTI0MzEyNmMifQ.mhf7E_aNN8i5s3lJg7WEZWTwdjh9p7r1VOJ_bIqb0CI'  # expired 02.21.19      
        }

        blk = JWTValidate()
        blk.start()
        self.configure_block(blk, config)
        blk.process_signals([{}])
        self.assert_num_signals_notified(1, blk)
        self.assertEqual('Token is expired', self.last_signal_notified().message)
        self.assertEqual(1, self.last_signal_notified().error)
        self.assertIsNone(self.last_signal_notified().token)
        blk.stop()

    def test_validate_token_without_expiration(self):
        config = {
          'key': 'secret',
          'algorithm': 'HS256',
          'validate_expiration': False,
          'input': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiNWM2ZGQ3YzYyYzFmZWRhNzUyNDMxMjZjIn0.4WVCdTEZap2914UCBesiFCZcW-DvAUCLemERgn0eFwQ'  # no expiration      
        }

        blk = JWTValidate()
        blk.start()
        self.configure_block(blk, config)
        blk.process_signals([{}])
        self.assert_num_signals_notified(1, blk)
        self.assertEqual('Token is valid', self.last_signal_notified().message)
        self.assertEqual(0, self.last_signal_notified().error)
        self.assertIsNotNone(self.last_signal_notified().token)
        self.assertEqual(type(self.last_signal_notified().token), str)
        self.assertEqual(jwt.decode(self.last_signal_notified().token, 'secret', algorithms=['HS256']), {'user_id': '5c6dd7c62c1feda75243126c'})
        blk.stop()

    