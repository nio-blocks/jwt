Validate
========
The Validate block evaluates a JWT token and determines whether it is valid, both in terms of being able to decrypt it, as well as (optionally) if it is expired based on the `exp` claim.

Properties
----------
- **JWT Secret**: The secret used to encrypt the token.
  - default `[[JWT_SECRET]]` (environment variable)
- **Hashing Algorithm**: The type of encryption used to create the token.
  - default `HS256`
- **Token Value**: The attribute that holds the token value.
  - default: `{{ $headers.get(\'Authorization\').split()[1] }}`
- **Validate Expires Claim**: Validate the token's `exp` claim as expired or not
  - default: `true`
- **Exclude Existing?**: If checked (true), the attributes of the incoming signal will be excluded from the outgoing signal. If unchecked (false), the attributes of the incoming signal will be included in the outgoing signal.

Outputs
-------
- **Valid**: Token is valid
- **Not Valid**: Token is not valid

Commands
--------
None
