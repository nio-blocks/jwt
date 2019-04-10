Create
======
The Create block will generate a JWT token encrypted with the selected algorithm.

Properties
----------
- **JWT Secret**: The secret used to encrypt the token.
  - default `[[JWT_SECRET]]` (environment variable)
- **Hashing Algorithm**: The type of encryption used to create the token.
  - default `HS256`
- **Valid For Minutes (exp claim)**: The TTL for the token, in minutes, based on UTC time.
  - default `60`
- **Claims**: A list of [name/value pairs](https://www.iana.org/assignments/jwt/jwt.xhtml). Examples:
    - name: str
    - profile: object
- **Exclude Existing?**: If checked (true), the attributes of the incoming signal will be excluded from the outgoing signal. If unchecked (false), the attributes of the incoming signal will be included in the outgoing signal.

Outputs
-------
- **Success**: 1 signal containing an object {'token': String}
- **Error**: 1 signal containing an object {'message': String}

Commands
--------
None

