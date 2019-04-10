from nio import Block
from nio.block.mixins import EnrichSignals
from nio.properties import PropertyHolder, StringProperty, Property, ListProperty, VersionProperty
from nio.block import output
from .jwt_base import JWTBase
from jwt.exceptions import PyJWTError 
import jwt

class ClaimField(PropertyHolder):
    name = StringProperty(title='Name', order=0)
    value = Property(title='Value', order=1)

@output('success', label='Success', default=True)
@output('error', label='Error')
class JWTCreate(EnrichSignals, JWTBase):
    version = VersionProperty('0.1.0')

    exp_minutes = Property(title='Valid For Minutes (blank for no exp claim)', order=3, allow_none=True)
    claims = ListProperty(ClaimField, title='Claims', order=4, allow_none=True)

    def process_signal(self, signal, input_id=None):
        _key = self.key(signal)
        _algorithm = self.algorithm(signal)
        _exp_minutes = self.exp_minutes(signal)
        _claims = self.claims(signal)
        _newclaims = {}

        try:
            if isinstance(_exp_minutes, int):
                  _newclaims['exp'] = self.set_new_exp_time(_exp_minutes)
            for claim in _claims:
                if claim.name(signal) is not 'exp':
                    _newclaims[claim.name(signal)] = claim.value(signal)

            _token = jwt.encode(_newclaims, _key, algorithm=_algorithm.value).decode('UTF-8')
            return self.notify_signals(self.get_output_signal({'token': _token }, signal), 'success')

        # jwt.encode throws ValueError if key is in wrong format
        except (PyJWTError, ValueError) as e: 
            self.notify_signals(self.get_output_signal({'message': e.args[0] }, signal), 'error')

