from enum import Enum
from nio import Block
from nio.properties import SelectProperty, Property
from nio.util.discovery import not_discoverable

class Algorithms(Enum):
    HS256 = 'HS256'
    HS384 = 'HS384'
    HS512 = 'HS512'
    ES256 = 'ES256'
    ES384 = 'ES384'
    ES512 = 'ES512'
    RS256 = 'RS256'
    RS384 = 'RS384'
    RS512 = 'RS512'
    PS256 = 'PS256'
    PS384 = 'PS384'
    PS512 = 'PS512'

@not_discoverable
class JWTBase(Block):
    key = Property(title='JWT Secret', default='[[JWT_SECRET]]', order=1)
    algorithm = SelectProperty(Algorithms, title='Hashing Algorithm', default=Algorithms.HS256, order=2)
