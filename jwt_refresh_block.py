from nio import Block
from nio.block.mixins import EnrichSignals
from nio.properties import BoolProperty, SelectProperty, StringProperty, Property, ListProperty, VersionProperty, IntProperty
from .jwt_base import JWTBase
import jwt
import datetime

class JWTRefresh(EnrichSignals, JWTBase):
    input = StringProperty(title='Token Value', default='{{ $headers.get(\'Authorization\').split()[1] }}', order=3)
    exp_minutes = IntProperty(title='Valid For Minutes (exp claim)', default=60, order=4)
    version = VersionProperty('0.1.0')

    def process_signals(self, signals):
        _key = self.key()
        _algorithm = self.algorithm()

        output_signals = []

        for signal in signals:
            _token = self.input(signal)
            _exp_minutes = self.exp_minutes(signal)
            _claims = None

            try:
                _claims = jwt.decode(_token, _key, algorithm=_algorithm.value)
            except Exception as e:
                output_signals.append(self.get_output_signal({'token': None, 'error': 1, 'message': 'Could not decrypt existing token: {}'.format(e)}, signal))
                break

            try:
                if 'exp' in _claims and datetime.datetime.utcnow().timestamp() > int(_claims['exp']):
                    output_signals.append(self.get_output_signal({'token': None, 'error': 1, 'message': 'Token is expired.' }, signal))
                    break
            except Exception as e:
                output_signals.append(self.get_output_signal({'token': None, 'error': 1, 'message': 'Error calculating token expiration: {}'.format(e)}, signal))
                break

            try:
                if 'exp' in _claims:
                    _claims['exp'] = int((datetime.datetime.utcnow() + datetime.timedelta(minutes=_exp_minutes)).timestamp())
                token = jwt.encode(_claims, _key, algorithm=_algorithm.value)
                output_signals.append(self.get_output_signal({'token': token.decode('UTF-8'), 'error': 0, 'message': 'Token refresh successful'}, signal))
            except Exception as e:
                output_signals.append(self.get_output_signal({'token': None, 'error': 1, 'message': 'Could not create new token: {}'.format(e)}, signal))

        self.notify_signals(output_signals)
