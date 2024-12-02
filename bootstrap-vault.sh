#!/bin/bash

###############################
#### Environment variables ####
###############################
CLUSTER_DOMAIN=cluster.local
VAULT_NUMBER_NODE=3
VAULT_CLUSTER_NAMESPACE=vault
VAULT_CLUSTER_PORT=8200

#######################
#### Log functions ####
#######################
info() {
  printf "\r  [ \033[00;34m..\033[0m ] %s\n" "$1"
}
process() {
  printf "\r  [ \033[0;33m>>\033[0m ] %s\n" "$1"
}
success() {
  printf "\r\033[2K  [ \033[00;32mOK\033[0m ] %s\n" "$1"
}
fail() {
  printf "\r\033[2K  [\033[0;31mFAIL\033[0m] %s\n" "$1"
  exit 1
}

############################
#### Initialize process ####
############################
info "======= Starting initialize Vault Cluster ======="

VAULT_ADDR=http://vault-0.vault-internal.$VAULT_CLUSTER_NAMESPACE.svc.$CLUSTER_DOMAIN:$VAULT_CLUSTER_PORT
VAULT_INIT=$(vault operator init --address $VAULT_ADDR -key-shares=5 -key-threshold=3 2>&1) # (key-shares=5 and key-threshold=3)

# Check for errors during initialization
if [[ $? -ne 0 ]]; then
  fail "Vault initialization failed: $VAULT_INIT"
else
  success "Vault initialization successfully"
fi

# Wait for Cluster is running
sleep 5

# Saved Init to tmp file, just for dev-test
echo $VAULT_INIT >/tmp/unseal.txt

########################
#### Unseal process ####
########################
# Just need 3 key for unseal process (Because key-threshold=3)
UNSEAL_KEY_1=$(echo "$VAULT_INIT" | grep "Unseal Key 1" | awk '{print $4}')
UNSEAL_KEY_2=$(echo "$VAULT_INIT" | grep "Unseal Key 2" | awk '{print $4}')
UNSEAL_KEY_3=$(echo "$VAULT_INIT" | grep "Unseal Key 3" | awk '{print $4}')

# Unseal Vault
UNSEAL_KEYS=("$UNSEAL_KEY_1" "$UNSEAL_KEY_2" "$UNSEAL_KEY_3")

# Loop through each vault pod
for ((i = 0; i < $VAULT_NUMBER_NODE; i++)); do
  count=1
  for KEY in "${UNSEAL_KEYS[@]}"; do
    # Execute the unseal command in the vault pod
    UNSEAL=$(
      vault operator unseal --address http://vault-$i.vault-internal.$VAULT_CLUSTER_NAMESPACE.svc.$C
      LUSTER_DOMAIN:$VAULT_CLUSTER_PORT $KEY 2>&1
    )
    # Check for errors during unsealing
    if [[ $? -ne 0 ]]; then
      fail "Vault unsealing failed"
    else
      process "Vault node-$i is unseal $count/3"
    fi
    ((count++))
    sleep 1
  done
done

sleep 2

# Login to Vault
ROOT_TOKEN=$(echo "$VAULT_INIT" | grep "Root Token" | awk '{print $4}')
LOGIN=$(vault login --address $VAULT_ADDR $ROOT_TOKEN 2>&1)
if [[ $? -ne 0 ]]; then
  fail "Vault login failed: $LOGIN"
else
  success "Vault login successfully"
fi

# Check Vault status
info "Check Vault status"
vault status --address $VAULT_ADDR

# Check HA Raft
info "Check Vault HA Raft"
vault operator raft list-peers --address $VAULT_ADDR

###################################
#### Predefined configurations ####
###################################
info "Apply predefined configurations"
export VAULT_ADDR=http://vault-0.vault-internal.$VAULT_CLUSTER_NAMESPACE.svc.$CLUSTER_DOMAIN:$VAULT_CLUSTER
_PORT

# Define Admin Policy
vault policy write admin-policy - <<EOF
  # admin-policy
  ## Allow access to all secret paths
  path "secret/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
  }

  ## Allow management of authentication methods
  path "auth/*" {
    capabilities = ["create", "read", "update", "delete", "list", "sudo"]
  }

  ## Allow management of policies
  path "sys/policies/acl/*" {
    capabilities = ["create", "read", "update", "delete", "list", "sudo"]
  }

  ## Allow management of identities
  path "identity/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
  }

  ## Allow general management of Vault
  path "sys/*" {
    capabilities = ["create", "read", "update", "delete", "list", "sudo"]
  }
EOF

success "Vault create policy success."

# Enabled Userpass authentication method
info "Start enable userpass authentication method"
ENABLE_AUTH_USERPASS=$(vault auth enable userpass 2>&1)
if [[ $? -ne 0 ]]; then
  fail "Vault enable userpass authentication method: $ENABLE_AUTH_USERPASS"
else
  success "$ENABLE_AUTH_USERPASS"
fi

# Generate a password
info "Start generating admin password"
password=$(tr -dc 'A-Za-z0-9!@#?%=' </dev/urandom | head -c 15)
echo "Admin Password: $password" >/tmp/admin_password.txt # Store admin password for dev
success "Generate admin password successfully"

# Create Admin account
info "Start create admin account"
CREATE_ADMIN_USER=$(vault write auth/userpass/users/admin password="$password" 2>&1)
if [[ $? -ne 0 ]]; then
  fail "Vault create user admin: $CREATE_ADMIN_USER"
else
  success "$CREATE_ADMIN_USER"
fi

# Create Admin Entity
info "Start create Admin entity"
ADMIN_ENTITY=$(vault write identity/entity name="admin" policies="admin-policy" 2>&1)
if [[ $? -ne 0 ]]; then
  fail "Vault create admin entity failed: $ADMIN_ENTITY"
else
  success "$ADMIN_ENTITY"
fi

# Create Admin alias entity
info "Start create Admin alias entity"
ADMIN_ENTITY_ID=$(vault read -field=id identity/entity/name/admin)
ACCESSOR=$(vault auth list | grep 'userpass/' | awk '{print $3}')
CREATE_ALIAS=$(vault write identity/entity-alias name="admin" \
  canonical_id="$ADMIN_ENTITY_ID" \
  mount_accessor="$ACCESSOR" 2>&1)
if [[ $? -ne 0 ]]; then
  fail "Vault create admin entity alias failed: $CREATE_ALIAS"
else
  success "$CREATE_ALIAS"
fi

# Enable Kubernetes authentication method
info "Start enable Kubernetes authentication method"
ENABLE_K8S_AUTH_METHOD=$(vault auth enable -path kubernetes kubernetes 2>&1)
if [[ $? -ne 0 ]]; then
  fail "Vault enable kubernetes authentication method failed: $ENABLE_K8S_AUTH_METHOD"
else
  success "$ENABLE_K8S_AUTH_METHOD"
fi

# Configures Kubernetes authentication method
info "Start configures Kubernetes authentication method"
CONFIG_K8S_AUTH_METHOD=$(vault write auth/kubernetes/config \
  kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443" 2>&1)
if [[ $? -ne 0 ]]; then
  fail "Vault config kubernetes authentication method failed: $CONFIG_K8S_AUTH_METHOD"
else
  success "$CONFIG_K8S_AUTH_METHOD"
fi

# Enable kv-v2 secrets engine for CMP
info "Start enable kv-v2 secrets engine"
ENABLE_SECRET_CMP=$(vault secrets enable -path=secret/cmp kv-v2 2>&1)
if [[ $? -ne 0 ]]; then
  fail "Enable kv-v2 secrets engine CMP failed: $ENABLE_SECRET_CMP"
else
  success "$ENABLE_SECRET_CMP"
fi

success "Apply predefined configurations successfully."

success "======= Bootstrap Vault cluster successfully ======="

sleep 10000
