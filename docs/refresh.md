Create
======
The Refresh block accepts a valid JWT token and returns a new token with an updated `exp` timestamp.

Properties
----------
- **JWT Secret**: The secret used to encrypt the token.
  - default `[[JWT_SECRET]]` (environment variable)
- **Hashing Algorithm**: The type of encryption used to create the token.
  - default `HS256`
- **Token Value**: The attribute that holds the token value.
  - default: `{{ $headers.get(\'Authorization\').split()[1] }}`
- **Valid For Minutes (exp claim)**: The TTL for the token, in minutes.
  - default: `60`
- **Exclude Existing?**: If checked (true), the attributes of the incoming signal will be excluded from the outgoing signal. If unchecked (false), the attributes of the incoming signal will be included in the outgoing signal.

Outputs
-------
One outgoing signal containing the updated token.

Commands
--------
None
