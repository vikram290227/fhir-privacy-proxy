# Inferno Community Edition — Setup Guide

This guide walks through configuring
[Inferno](https://inferno.healthit.gov/) to run SMART-on-FHIR
conformance tests against the FHIR Privacy Proxy.

## Prerequisites

- The full stack is running (`make up`)
- Docker (Inferno runs as a container)

## 1. Start Inferno

```bash
docker run -d --name inferno \
  --network host \
  -p 4567:4567 \
  infernocommunity/inferno-core:latest
```

> `--network host` lets Inferno reach the proxy and Keycloak on
> localhost ports.

Open the Inferno UI at **http://localhost:4567**.

## 2. Configure the test session

Select **US Core v3.1.1** or **SMART App Launch** and enter:

| Field               | Value |
|---------------------|-------|
| FHIR Server URL     | `http://localhost:8080/fhir/r4` |
| Client ID           | `fhir-privacy-proxy` |
| Token Endpoint      | `http://localhost:8180/realms/hospital-a/protocol/openid-connect/token` |
| Authorize URL       | `http://localhost:8180/realms/hospital-a/protocol/openid-connect/auth` |
| JWKS URL            | `http://localhost:8180/realms/hospital-a/protocol/openid-connect/certs` |

## 3. CapabilityStatement / metadata

The proxy exposes `/fhir/r4/metadata` **without authentication**, as
required by the FHIR and SMART specifications. This endpoint proxies
the upstream HAPI CapabilityStatement and rewrites the
`implementation.url` field to point at the proxy so Inferno's server
URL validation passes.

Verify it manually:

```bash
curl -s http://localhost:8080/fhir/r4/metadata | python3 -m json.tool | head -20
```

## 4. Expected test outcomes

| Suite                          | Expected |
|--------------------------------|----------|
| CapabilityStatement / metadata | Pass     |
| SMART bearer token access      | Pass     |
| Read Patient by ID             | Pass (redaction applied per role) |
| Search by name/birthdate       | Pass     |
| Write / create resources       | Fail (proxy is read-only by design) |
| Bulk Data export               | Fail (not implemented) |

Failures on write/bulk-data endpoints are expected — the proxy is a
privacy-enforcement read layer, not a full FHIR server.

## 5. Using the public HAPI sandbox

To test against real data instead of the local HAPI container, set:

```bash
# In .env or docker-compose override
FHIR_UPSTREAM=http://hapi.fhir.org/baseR4
```

Then restart the proxy:

```bash
make down && make up
```

Run the smoke test:

```bash
make test-public
```

## 6. Troubleshooting

- **Inferno can't reach the proxy**: Ensure `--network host` or use
  the Docker bridge IP (`172.17.0.1`) instead of `localhost`.
- **Token errors**: Verify Keycloak is up (`curl http://localhost:8180`)
  and the realm `hospital-a` exists.
- **metadata 404**: Ensure you're running the latest proxy build with
  the `/fhir/r4/metadata` endpoint. Run `make build && make up`.
