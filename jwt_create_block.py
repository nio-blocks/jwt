from nio import Block
from nio.block.mixins import EnrichSignals
from nio.properties import PropertyHolder, StringProperty, Property, ListProperty, VersionProperty, IntProperty
from .jwt_base import JWTBase
import jwt
import datetime

class ClaimField(PropertyHolder):
    name = StringProperty(title='Name', order=0)
    value = Property(title='Value', order=1)

class JWTCreate(EnrichSignals, JWTBase):
    exp_minutes = Property(title='Valid For Minutes (exp claim)', default=60, order=3, allow_none=True)
    claims = ListProperty(ClaimField, title='Claims', order=4, allow_none=True)
    version = VersionProperty('0.1.0')

    def process_signals(self, signals):
        _key = self.key()
        _algorithm = self.algorithm()
        _exp_minutes = self.exp_minutes()

        output_signals = []

        for signal in signals:
            _claims = self.claims(signal)
            _newclaims = {}

            if _exp_minutes is not None and _exp_minutes is not '':
                _newclaims['exp'] = int((datetime.datetime.utcnow() + datetime.timedelta(minutes=_exp_minutes)).timestamp())
            for claim in _claims:
                if claim.name(signal) is not 'exp':
                    _newclaims[claim.name(signal)] = claim.value(signal)

            try:
                token = jwt.encode(_newclaims, _key, algorithm=_algorithm.value).decode('UTF-8')
                print(token)
                output_signals.append(self.get_output_signal({'token': token, 'error': 0, 'message': 'Token creation successful' }, signal))
            except Exception as e:
                output_signals.append(self.get_output_signal({'token': None, 'error': 1, 'message': 'Could not create new token: {}'.format(e)}, signal))

        self.notify_signals(output_signals)
