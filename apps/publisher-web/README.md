# Traceless Publisher Web

Internal administration UI for the central intelligence publisher. It is intentionally deployed
separately from the customer-local operational application and proxies to four isolated publisher
surfaces:

- admin: accounts, installations and credentials
- review: staged records, publication and rejection
- ingest: reserved for normalized import workflows
- feed: public signing-key metadata

OIDC is the recommended production authentication method. Development mode can use separate
admin and reviewer service tokens; those values are held in React memory only and are never
written to browser storage.

The Compose publisher profile exposes the UI on `http://127.0.0.1:8200`.
