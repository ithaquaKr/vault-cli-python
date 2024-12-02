from vault_cli import *

client = VaultClient(url="http://127.0.0.1:8200/")
client.token = "hvs.9XnKjWxU2LgSXkFWCeFXj7kS"
client.auth()

cfg = load_config_file("./vault-config.yaml")

commands = Commands(client=client)
# Test Auth Method
