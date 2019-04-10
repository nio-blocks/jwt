from nio.block.mixins import EnrichSignals
from nio.properties import StringProperty, VersionProperty
from nio.block import output
from .jwt_base import JWTBase
import jwt
from jwt.exceptions import PyJWTError


@output('success', label='Valid', default=True)
@output('error', label='Not Valid')
class JWTValidate(EnrichSignals, JWTBase):

    version = VersionProperty('0.1.0')
    input = StringProperty(
        title='Token Value',
        default='{{ $headers.get(\'Authorization\').split()[1] }}',
        order=4)

    def process_signal(self, signal, input_id=None):
        _key = self.key(signal)
        _algorithm = self.algorithm(signal)
        _token = self.input(signal)

        try:
            jwt.decode(_token, _key, algorithms=[_algorithm.value])
            return self.get_output_signal({'token': _token}, signal)

        except PyJWTError as e:
            self.notify_signals(
                self.get_output_signal({'message': e.args[0]}, signal),
                'error')
