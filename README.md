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

## Safe runtime rendering

Service names must be single filename components. The runtime directory and its `files/` directory are mode
`0700`; outputs and the value-free ownership manifest are mode `0600`. Later renders withdraw only outputs
recorded in that manifest and no longer declared for this host, preserving unrelated files. Use a fresh runtime
directory when adopting this behavior: older renderers left no ownership records, so their files are not guessed
at or deleted. Symlinked paths and malformed or foreign-host manifests are refused.

Rendering requires Linux's util-linux `flock`. Its kernel lock refuses concurrent renderers and releases when
the renderer exits or is killed, without deleting the empty lock file. Values are fetched before existing outputs
change. Replacement is atomic per file, not for the entire directory. A pending manifest retains ownership of
both generations before output changes; retry can reconcile an interrupted update. Success is reported only
after replacements and withdrawals finish. Retry a failed render before reloading consumers.

Deployment owns startup and periodic execution, failure recovery, and controlled reload or restart so running
processes receive rotation. Successful rendering does not prove that a process reloaded or a grant was renewed.

## Where code finds credentials

Code reads its credentials only from `CREDENTIALS_DIRECTORY` (systemd's name for a process's credentials
directory), never from a file in a home directory: `credentialPath('kalshi.env')`,
`credentialPath('fastmail/<account>.json')` (`@red-cup-engineering/credential-custody-service/keep`). A file
credential renders at the relative path its code reads when its consumer records one (`path`);
`credentials place-files --root ~/.config/<holder>` records those paths for credentials imported from such a
directory.

A credential a process obtains is kept, not written to a file of its own: `keepCredential({ service, path | variable,
value })` seals it into the store (`CREDENTIALS_STORE`) for this host (`CREDENTIALS_HOST`), re-renders, and commits
and pushes the store.
