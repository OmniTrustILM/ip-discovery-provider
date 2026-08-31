# Network Discovery Provider

> This repository is part of the commercial open-source project ILM. You can find more information about the project at the [ILM](https://github.com/OmniTrustILM/ilm) repository, including the contribution guide.

Network Discovery Provider implements the logic of discovering certificates that are distributed over the network.

Network Discovery Provider can discover certificates from:
- Intranet - Scan the entire infrastructure inside an organization and discover the certificates from application and 
sites that are not exposed to the outside worked
- Internet - If the provider has access to the internet, It can discover certificates from any publicly accessible URLs

The `Connector` provides various options during the certificate, including:
- Single Host Scan
- Multiple Host Scan
- Single / Multi Subnet Scan
- Single / All port Scan

## Short Process Description

`Connector` discovers the certificates from the host without increasing the network traffic and congestion. When the connector receives the request to scan the host, it tries to connect to the ssl port (which can be left default to `443` or provided with custom value), captures the certificates and parses them. Once the certificates are successfully gathered, it is then sent back to the `Core` for storage and parsing. `Core` takes care of the rest.

To know more about `Core`, refer to [Core](https://github.com/OmniTrustILM/core).

## Interfaces

Network Discovery Provider implements the `Discovery Provider` Interface from the ILM Interfaces. To learn more about the interfaces and end points, refer to the [Interfaces](https://github.com/OmniTrustILM/interfaces).

For more information regarding the `Discovery`, please refer to the [documentation](https://docs.otilm.com).

## Docker container

Network Discovery Provider is provided as a Docker container. Use the `hub.omnitrustregistry.com/ilm/ip-discovery-provider:tagname` to pull the required image from the repository. It can be configured using the following environment variables:

| Variable        | Description                                              | Required                                           | Default value |
|-----------------|----------------------------------------------------------|----------------------------------------------------|---------------|
| `JDBC_URL`      | JDBC URL for database access                             | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`         |
| `JDBC_USERNAME` | Username to access the database                          | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`         |
| `JDBC_PASSWORD` | Password to access the database                          | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`         |
| `DB_SCHEMA`     | Database schema to use                                   | ![](https://img.shields.io/badge/-NO-red.svg)      | `network`     |
| `PORT`          | Port where the service is exposed                        | ![](https://img.shields.io/badge/-NO-red.svg)      | `8080`        |
| `JAVA_OPTS`     | Customize Java system properties for running application | ![](https://img.shields.io/badge/-NO-red.svg)      | `N/A`         |

### Java runtime

The image does not ship a full JRE. It carries a custom runtime built with `jlink`, containing only
the modules the application resolves plus `jdk.crypto.ec` for the elliptic-curve handshakes and
certificates the scanner encounters.

This constrains `JAVA_OPTS`. Anything needing a module outside that set will fail to start rather
than being ignored — a `-javaagent` JMX or APM agent (`java.instrument` is present, but the agent's
own dependencies may not be), remote JMX (`jdk.management.agent`), or an additional security
provider. Check the modules actually present with:

```
docker run --rm --entrypoint sh hub.omnitrustregistry.com/ilm/ip-discovery-provider:tagname -c 'java --list-modules'
```

If you need a module that is absent, raise an issue rather than working around it — the module set
is derived at build time and can be extended through the image's `ADDITIONAL_MODULES` build argument.
