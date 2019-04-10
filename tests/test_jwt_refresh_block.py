from nio.signal.base import Signal
from nio.testing.block_test_case import NIOBlockTestCase
from ..jwt_refresh_block import JWTRefresh
import jwt
import datetime


class TestJWTRefresh(NIOBlockTestCase):

    good_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1ODIzMjg0OTIsInVzZXJfaWQiOiI1YzZkZDdjNjJjMWZlZGE3NTI0MzEyNmMifQ.tlrHNvcrki94CzkLyZSXKlBDI2skWhNOJsQ0Sh4fB_I' # expires 02.21.20 # noqa
    expired_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1NTA3OTI2NDEsInVzZXJfaWQiOiI1YzZkZDdjNjJjMWZlZGE3NTI0MzEyNmMifQ.mhf7E_aNN8i5s3lJg7WEZWTwdjh9p7r1VOJ_bIqb0CI' # expired 02.21.19 # noqa
    no_expire_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiNWM2ZGQ3YzYyYzFmZWRhNzUyNDMxMjZjIn0.4WVCdTEZap2914UCBesiFCZcW-DvAUCLemERgn0eFwQ' # noqa

    config = {
      'key': 'secret',
      'algorithm': 'HS256',
      'validate_expiration': True,
      'input': '{{ $headers.get(\'Authorization\').split()[1] }}'
    }

    def test_refresh_token_with_passing_expiration(self):
        config = self.config
        config['exp_minutes'] = 60
        blk = JWTRefresh()

        blk.start()
        self.configure_block(blk, config)
        expected_expiration = int((
            datetime.datetime.utcnow() +
            datetime.timedelta(minutes=config['exp_minutes'])).timestamp())
        blk.process_signals([
            Signal({'headers': {'Authorization': 'Bearer ' + self.good_token}})
        ])
        self.assert_num_signals_notified(1, blk, 'success')
        self.assert_num_signals_notified(0, blk, 'error')
        self.assertIsNotNone(self.last_signal_notified().token)
        self.assertEqual(type(self.last_signal_notified().token), str)
        self.assertEqual(
            jwt.decode(
                self.last_signal_notified().token,
                'secret',
                algorithms=['HS256']),
            {
                'exp': expected_expiration,
                'user_id': '5c6dd7c62c1feda75243126c'
            })
        blk.stop()

    def test_refresh_token_with_failing_expiration(self):
        config = self.config
        config['exp_minutes'] = 60
        blk = JWTRefresh()

        blk.start()
        self.configure_block(blk, config)
        blk.process_signals([
            Signal({'headers': {
                'Authorization': 'Bearer ' + self.expired_token}})
        ])
        self.assert_num_signals_notified(0, blk, 'success')
        self.assert_num_signals_notified(1, blk, 'error')
        self.assertEqual(
            'Signature has expired', self.last_signal_notified().message)
        blk.stop()

    def test_refresh_token_without_expiration(self):
        config = self.config
        config['exp_minutes'] = None
        blk = JWTRefresh()

        blk.start()
        self.configure_block(blk, config)
        blk.process_signals([
            Signal({'headers': {
                'Authorization': 'Bearer ' + self.no_expire_token}})
        ])
        self.assert_num_signals_notified(1, blk, 'success')
        self.assert_num_signals_notified(0, blk, 'error')
        self.assertIsNotNone(self.last_signal_notified().token)
        self.assertEqual(type(self.last_signal_notified().token), str)
        self.assertEqual(
            jwt.decode(
                self.last_signal_notified().token,
                'secret',
                algorithms=['HS256']),
            {'user_id': '5c6dd7c62c1feda75243126c'})
        blk.stop()
