from nio import Block
from nio.block.mixins import EnrichSignals
from nio.properties import BoolProperty, SelectProperty, StringProperty, Property, ListProperty, VersionProperty
from .jwt_base import JWTBase
import jwt
import datetime

class JWTValidate(EnrichSignals, JWTBase):
    input = StringProperty(title='Token Value', default='{{ $headers.get(\'Authorization\').split()[1] }}', order=4)
    validate_expiration = BoolProperty(title='Validate Expires Claim', default=True, order=5)
    version = VersionProperty('0.1.0')

    def process_signals(self, signals):
        _key = self.key()
        _algorithm = self.algorithm()
        _validate_expiration = self.validate_expiration()

        output_signals = []

        for signal in signals:
            _token = self.input(signal)
            _claims = None

            try:
                _claims = jwt.decode(_token, _key, algorithms=[_algorithm.value])
            except Exception as e:
                output_signals.append(self.get_output_signal({'token': None, 'error': 1, 'message': 'Could not decrypt existing token: {}'.format(e)}, signal))
                break

            try:
                if _validate_expiration is False or ('exp' in _claims and datetime.datetime.utcnow().timestamp() < int(_claims['exp'])):
                    output_signals.append(self.get_output_signal({'token': _token, 'error': 0, 'message': 'Token is valid' }, signal))
                else:
                    output_signals.append(self.get_output_signal({'token': None, 'error': 1, 'message': 'Token is expired'}, signal))
            except Exception as e:
                output_signals.append(self.get_output_signal({'token': None, 'error': 1, 'message': 'Error calculating token expiration: {}'.format(e)}, signal))
                break

        self.notify_signals(output_signals)
