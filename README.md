# Vault CLI Tool

A command-line interface tool for managing HashiCorp Vault clusters, focusing on automation of common operational tasks like initialization, unsealing, and policy management.

## Features

- **Cluster Management**
  - Initialize Vault clusters
  - Unseal Vault nodes
  - Manage multiple Vault instances in Kubernetes
- **Policy Management**

  - Sync policies between configuration and Vault
  - Remove orphaned policies
  - Exclude system policies (root, default) from sync operations

- **Authentication**
  - Support for multiple authentication methods
  - Token-based authentication
  - User/password authentication

## Prerequisites

- Python 3.9+
- Access to a Kubernetes cluster running Vault
- The following Python packages (specified in [requirements.txt](requirements.txt)):
  - click
  - hvac (HashiCorp Vault client)
  - kubernetes-client

## Installation

1. Clone this repository
2. Install dependencies:

   ```sh
   pip install -r requirements.txt
   ```

## Configuration

Create a vault configuration file (vault-config.yaml) with your specific settings. See vault-config-example.yaml for reference.

## Usage

### Basic Commands

Initialize a new Vault cluster:

```sh
python vault_cli.py init --namespace vault
```

Unseal Vault instances:

```sh
python vault_cli.py unseal --instance vault-0 --namespace vault
```

Sync policies:

```sh
python vault_cli.py sync-policy --remove-orphans
```

## Development

To run in development mode:

1. Start a local Vault server using the provided Makefile:

```sh
make recreate
```

2. Port forward the Vault service:

```sh
make pf
```
