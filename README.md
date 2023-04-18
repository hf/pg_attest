pg\_attest
==========

`pg_attest` is a PostgreSQL extension that provides attestations about the
current role and system. These can then be used to base trust in other systems.

For example, you can use an OIDC attestation (a JWT) to authorize calls to AWS
or Google Cloud APIs. You can also use it to identify and authorize calls to
your own custom APIs based on the access an app has to your database,
simplifying secure identification across app components.

You can obtain an attestation by calling:

```sql
SELECT pg_attest.attest();
```

This returns back a cryptographically signed attestation that contains the
`current_user` and `session_user` and other information about the database.

It does this by calling the relevant PostgreSQL commands from within a C
extension, making it impossible to tamper with the result. Furthermore, the
signature is issued by an agent running alongside the database. The extension
and agent talk over a UNIX SEQPACKET connection, exchanging JSON messages. An
attestation request is checked, then an attestation is issued based on the
config settings of the agent. Finally it is returned to the caller.

## Status

Early development.

