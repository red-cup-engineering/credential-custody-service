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

## On a host

A host's services read their credentials from a runtime directory rendered from the store, never from files kept
in a home directory. `scripts/render-host.mjs` takes its configuration from the environment (`CREDENTIALS_STORE`,
`CREDENTIALS_HOST`, `CREDENTIALS_RENDER_TO`, `CREDENTIALS_PULL=1`) so a deployment runs it as a oneshot unit on a
timer; each service then reads `<dir>/<service>.env`. A file credential (a key, a service account) is rendered to
`<dir>/files/<id>`; `credentials bind-file <id> --service <s> --variable NAME` puts `NAME=<that path>` in the
service's env file, so the service never names a path of its own.
