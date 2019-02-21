from nio.signal.base import Signal
from nio.testing.block_test_case import NIOBlockTestCase
from ..jwt_create_block import JWTCreate
import jwt
import datetime

class TestJWTCreate(NIOBlockTestCase):

    def test_create_token_without_expiration(self):
        config = {
          'key': 'secret',
          'algorithm': 'HS256',
          'exp_minutes': None,
          'claims': [{ 'name': 'user_id', 'value': 'myUserId'}]
        }

        blk = JWTCreate()
        blk.start()
        self.configure_block(blk, config)
        blk.process_signals([{}])
        self.assert_num_signals_notified(1, blk)
        self.assertEqual('Token creation successful', self.last_signal_notified().message)
        self.assertEqual(0, self.last_signal_notified().error)
        self.assertIsNotNone(self.last_signal_notified().token)
        self.assertEqual(type(self.last_signal_notified().token), str)
        self.assertEqual(jwt.decode(self.last_signal_notified().token, 'secret', algorithms=['HS256']), { 'user_id': 'myUserId'})
        blk.stop()

    def test_create_token_with_expiration(self):
        config = {
          'key': 'secret',
          'algorithm': 'HS256',
          'exp_minutes': 60,
          'claims': [{ 'name': 'user_id', 'value': 'myUserId'}]
        }

        blk = JWTCreate()
        blk.start()
        self.configure_block(blk, config)
        expected_expiration= int((datetime.datetime.utcnow() + datetime.timedelta(minutes=config['exp_minutes'])).timestamp())
        blk.process_signals([{}])
        self.assert_num_signals_notified(1, blk)
        self.assertEqual('Token creation successful', self.last_signal_notified().message)
        self.assertEqual(0, self.last_signal_notified().error)
        self.assertIsNotNone(self.last_signal_notified().token)
        self.assertEqual(type(self.last_signal_notified().token), str)
        self.assertEqual(jwt.decode(self.last_signal_notified().token, 'secret', algorithms=['HS256']), { 'exp': expected_expiration, 'user_id': 'myUserId'})
        blk.stop()

    def test_create_token_with_rsa_and_keys(self):
        config = {
          'key': '''-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxcgXtc9ejo7dQkOAahN2SNI8DM7KnRpWraqqRrVFpE7jC8yx
XooiR+Lv5SHtLVK6xy3cuQVePIUff0Du7/mB0rCnZiDAXaZwiYhn56u3VT1w8jAz
KoSfnokgS6punssg2lyeqDhSsEMeaNT7EI2mwpY+l2hotWotLYNjdfLoP9L1LiCw
O3QV7X8khSE5re5UcMsPpJYV9cZXVA2NlVS/NOiONH8yc4/+kxRIh5UU9R54DVCe
3u+egawwdr2BB08AKwMbxUeZp0SzDbuEhBXH2Z/v+kndd7yEFU9uxgVPaawqdIyA
yr6ULm7xPSRSxiMqWVNfZUi3KemUFzc8/djsqQIDAQABAoIBAQCrY/HoA4OVVgg2
2/fz9FmUUVroXmsGKUTjyfk0vPFUqWfnWcJ6gomice4hSX0WwZJJ+FxFmXlISLQ6
ujJUkosF4T+vKMKKZSkwhZxFDnEY1N2DgnFUbwlDgOETsOWbhbs6fvieHfDJ/d/k
SGwotBfGmBw1aK0USKZNwoX2OEE6zDXKRu95hfiu+BP3zR1OAyQka/2zgmjA5NQT
dPh8TlnFZ08V9TVR3j9mK37Kntkw1+blnDOvV/jXZBHYRz6WviUwzSfiQ3EZ6GS8
rnZ2iI2EwJQIfwXkcRuhXnZEplt5768co5dk34FY3Mh1RMjPXOZeRKZgKXQejrLW
4PYltYdhAoGBAPJl6HwxrUQwh64Nla0COmnjxccL4agtTmqi0NllNN2IALmkIFm0
T3gfTwMB4Jmi52YCXwe60CCLR+TKohX+YQx1oh5UEVOR1RmzzayFiO6lt5nWN168
//uTciSOuhlK3EZaZuHvH5AhZH6ESOYU/d0YzyQmxwwKJUYQao06dwdLAoGBANDh
Qswkp2ZcbUMdthQ2I/xCTQALDhgojAZCMwWJavhXU7Syrn3XJQpqxzuKsS7WFjg+
NYY2WoYUQ7oAKU6OMO+134bESFNLThFptaVXci5IpsX2Z5t0a9PUEzQPbNHwv1WI
KHy94B1dSTBlWe/K52UAkOdzqWzGGv157TD6Ld9bAoGARuNisB9fCpgetdonMad7
KciA6Isi/SnyyuC+rzUX1smVXLUQ+OrwarLNSpXb91Ja1cxPulT51OqmpdRUvpXc
D+a++JuhTY1SgufAeHm85/3yybyKCNzBB/PA58wNxKPN840wlVZ3JpF9cDqDjzYI
YAaHXY0xnOXCrNDUOGUmti0CgYEAiqmfYEnM3wToe6+TmeM/DE0vNKIiHyN7oQP9
PuW0n1vJc6FSeLOEIWA1Fm/Bo6f3ZCrX+VrHyU5Wj3lf8oguMFN6KcrPgIvzLVgR
f8uHPvZ3z979dJNaqWqVvO+oe83oFm2nAvhBePzeg0Qk6iy2Y7R2fU+o3067yB1S
ujq6jRUCgYBEh0U9MD0XMrT7Pqug7qzQlTA+HOMBpFvVmFfwgxRdCdzr+ywKzFVC
Gp7fKL3Y2EeXaAhY91/vWrk/5lHlNR3rT6aq6qOAAIh0wyguhmGnjhQy/p1qVvH3
/FZ40KKKHkkIJvrzvx2R3BgmEpp1/IDmaMSZwSmyYwALpx+4KG6GUw==
-----END RSA PRIVATE KEY-----''',
          'algorithm': 'RS512',
          'exp_minutes': 60,
          'claims': [{ 'name': 'user_id', 'value': 'myUserId'}]
        }

        public_key_for_decypt = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxcgXtc9ejo7dQkOAahN2
SNI8DM7KnRpWraqqRrVFpE7jC8yxXooiR+Lv5SHtLVK6xy3cuQVePIUff0Du7/mB
0rCnZiDAXaZwiYhn56u3VT1w8jAzKoSfnokgS6punssg2lyeqDhSsEMeaNT7EI2m
wpY+l2hotWotLYNjdfLoP9L1LiCwO3QV7X8khSE5re5UcMsPpJYV9cZXVA2NlVS/
NOiONH8yc4/+kxRIh5UU9R54DVCe3u+egawwdr2BB08AKwMbxUeZp0SzDbuEhBXH
2Z/v+kndd7yEFU9uxgVPaawqdIyAyr6ULm7xPSRSxiMqWVNfZUi3KemUFzc8/djs
qQIDAQAB
-----END PUBLIC KEY-----'''

        blk = JWTCreate()
        blk.start()
        self.configure_block(blk, config)
        expected_expiration= int((datetime.datetime.utcnow() + datetime.timedelta(minutes=config['exp_minutes'])).timestamp())
        blk.process_signals([{}])
        self.assert_num_signals_notified(1, blk)
        self.assertEqual('Token creation successful', self.last_signal_notified().message)
        self.assertEqual(0, self.last_signal_notified().error)
        self.assertIsNotNone(self.last_signal_notified().token)
        self.assertEqual(type(self.last_signal_notified().token), str)
        self.assertEqual(jwt.decode(self.last_signal_notified().token, public_key_for_decypt, algorithms=['RS512']), { 'exp': expected_expiration, 'user_id': 'myUserId'})
        blk.stop()

    def test_fail_with_invalid_key_for_algorithm(self):
        config = {
          'key': 'secret',
          'algorithm': 'PS512',
          'exp_minutes': 60,
          'claims': [{ 'name': 'user_id', 'value': 'myUserId'}]
        }

        blk = JWTCreate()
        blk.start()
        self.configure_block(blk, config)
        blk.process_signals([{}])
        self.assert_num_signals_notified(1, blk)
        self.assertEqual('Could not create new token: Could not deserialize key data.', self.last_signal_notified().message)
        self.assertEqual(1, self.last_signal_notified().error)
        self.assertIsNone(self.last_signal_notified().token)
        blk.stop()