from nio import Block
from nio.block.mixins import EnrichSignals
from nio.properties import StringProperty, Property, VersionProperty
from nio.block import output
from .jwt_base import JWTBase
import jwt
from jwt.exceptions import PyJWTError

@output('success', label='Success')
@output('error', label='Error')
class JWTRefresh(EnrichSignals, JWTBase):
    version = VersionProperty('0.1.0')

    input = StringProperty(title='Token Value', default='{{ $headers.get(\'Authorization\').split()[1] }}', order=3)
    exp_minutes = Property(title='Valid For Minutes (exp claim)', order=4, allow_none=True)

    def process_signal(self, signal, input_id=None):
        _token = self.input(signal)
        _key = self.key(signal)
        _algorithm = self.algorithm(signal)
        _exp_minutes = self.exp_minutes(signal)

        try:
            _claims = jwt.decode(_token, _key, algorithms=[_algorithm.value])
        
            if isinstance(_exp_minutes, int):
                _claims['exp'] = self.set_new_exp_time(_exp_minutes)
            else:
                try:
                    del _claims['exp']
                except KeyError:
                    pass

            _token = jwt.encode(_claims, _key, algorithm=_algorithm.value)
            return self.notify_signals(self.get_output_signal({'token': _token.decode('UTF-8'), 'error': 0, 'message': 'Token refresh successful'}, signal), 'success')

        except PyJWTError as e:
            self.notify_signals(self.get_output_signal({'token': None, 'error': 1, 'message': e.args[0] }, signal), 'error') 