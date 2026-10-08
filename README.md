# Credential custody service

An organization's credentials in one store: a registry that says what each credential is, whose it is and which
hosts and services use it, and each value sealed (age, X25519) to the hosts allowed to open it plus recovery
recipients. The store is a directory in a services section's `data/credentials/`, tracked in that section's
repository; only `hosts/` (each host's own identity) is git-ignored.

```
credentials --store <section>/data/credentials --host <host> list
credentials … get <id>                       # a value, opened with this host's identity
credentials … render <service> --out <file>  # the env file a service runs with, from the registry
credentials … import <env-file> --service <s>
credentials … audit --scan <dir>             # plaintext copies, unstored secrets, rotations due, requests
credentials … request <id> --reason "…"     # what an agent does when the store lacks a credential
```

The cryptographic core (`cryptographic-data-service`) stays dependency-free; recipient sealing (age) lives here in
`src/recipient-seal.mjs`.

Custody only: authentication and authorization belong to the protocol and authority services that consume these
values.
