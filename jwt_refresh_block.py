from nio import Block
from nio.block.mixins import EnrichSignals
from nio.properties import BoolProperty, SelectProperty, StringProperty, Property, ListProperty, VersionProperty, IntProperty
from .jwt_base import JWTBase
import jwt

class JWTRefresh(EnrichSignals, JWTBase):
    version = VersionProperty('0.1.0')

    input = StringProperty(title='Token Value', default='{{ $headers.get(\'Authorization\').split()[1] }}', order=3)
    exp_minutes = IntProperty(title='Valid For Minutes (exp claim)', default=60, order=4)

    def process_signal(self, signal):
        _token = self.input(signal)
        _key = self.key(signal)
        _algorithm = self.algorithm(signal)
        _exp_minutes = self.exp_minutes(signal)

        try:
            _claims = jwt.decode(_token, _key, algorithms=[_algorithm.value])
        
            if 'exp' in _claims and isinstance(_exp_minutes, int):
                _claims['exp'] = self.set_new_exp_time(_exp_minutes)
        
            _token = jwt.encode(_claims, _key, algorithm=_algorithm.value)
            return self.notify_signals(self.get_output_signal({'token': _token.decode('UTF-8'), 'error': 0, 'message': 'Token refresh successful'}, signal))

        except Exception as e:
            self.notify_signals(self.get_output_signal({'token': None, 'error': 1, 'message': e.args[0] }, signal)) 