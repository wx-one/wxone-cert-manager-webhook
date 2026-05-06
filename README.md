# cert-manager DNS01 webhook for WX ONE

This webhook solver logs into the WX ONE API with an API key (not a normal user login)
and uses GraphQL to upsert/remove TXT records for DNS01 challenges.

## Build

docker build -t wxone/cert-manager-webhook-wxone:dev .

## Deploy

See deploy/ for example manifests. Apply `deploy/apiservice.yaml` as well; it registers the aggregated API that cert-manager talks to.
You must create a TLS secret named wx1-webhook-tls in cert-manager namespace.

The auth secret must contain a WX ONE API key id and secret, not your regular account password.

## Issuer config

solverName: wx1
groupName: acme.wx1.eu

Config:
- host: https://cmd.wx1.eu/api
- projectId: auto-resolved (optional)
- zoneId: auto-resolved by domain (optional)
- authCacheTTL: optional, default 4h
- authSecretRef: { name, namespace, usernameKey, passwordKey }

You can still set `projectId` explicitly if the zone lives outside the default project.
Future multi-project support will likely add aliases/selection for non-default project setups; until then, direct `projectId` remains the supported way to target a specific project.

Auth secret values:
- username: API key id
- password: API key secret
