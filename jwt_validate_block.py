from nio import Block
from nio.block.mixins import EnrichSignals
from nio.properties import BoolProperty, SelectProperty, StringProperty, Property, ListProperty, VersionProperty
from .jwt_base import JWTBase
import jwt

class JWTValidate(EnrichSignals, JWTBase):
    version = VersionProperty('0.1.0')

    input = StringProperty(title='Token Value', default='{{ $headers.get(\'Authorization\').split()[1] }}', order=4)

    def process_signal(self, signal):
        _key = self.key(signal)
        _algorithm = self.algorithm(signal)
        _token = self.input(signal)

        try:
            jwt.decode(_token, _key, algorithms=[_algorithm.value])
            return self.notify_signals(self.get_output_signal({'token': _token, 'error': 0, 'message': 'Token is valid' }, signal))

        except Exception as e:
            self.notify_signals(self.get_output_signal({'token': None, 'error': 1, 'message': e.args[0] }, signal))