import contextlib
import json
import os
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple, Type, TypeVar, Union

import click
import hvac
import hvac.exceptions as client_exception
import requests
import yaml
from kubernetes import client, config
from kubernetes.stream import stream
from pydantic import BaseModel

################
#### Typing ####
################

JSONValue = Union[str, int, float, bool, None, Dict[str, Any], List[Any]]
JSONDict = Dict[str, JSONValue]
T = TypeVar("T")

###################
#### Exception ####
###################


class VaultException(Exception):
    pass


class VaultAuthenticationError(VaultException):
    pass


class VaultSettingsError(VaultException):
    pass


class VaultConnectionError(VaultException):
    message: str = "Error while connecting to Vault"


class VaultInitialized(VaultException):
    message: str = "Vault is initialized"


class VaultNotInitialized(VaultException):
    message: str = "Vault is not initialized"


class VaultAPIException(VaultException):
    message: str = "Unexpected Vault error"

    def __init__(self, errors: Optional[Iterable[str]] = None) -> None:
        self.errors = errors

    def __str__(self) -> str:
        message = self.message
        if self.errors:
            message += "\n" + ("\n".join(self.errors))
        return message


class VaultInvalidRequest(VaultAPIException):
    message: str = "Invalid request"


class VaultUnauthorized(VaultAPIException):
    message: str = "Missing authentication"


class VaultInternalServerError(VaultAPIException):
    message: str = "Vault server error"


class VaultForbidden(VaultAPIException):
    message = "Insufficient access for interacting with the requested secret"


class VaultSealed(VaultAPIException):
    message = "Vault sealed or down"


###################
#### Utilities ####
###################


def execute_command_in_pod(
    pod_name: str,
    namespace: str,
    command: List[str],
):
    """
    Executes a command in a specified pod.

    Args:
        pod_name (str): Name of the pod.
        namespace (str): Namespace of the pod.
        command (list): List of commands to execute.
    """

    config.load_kube_config()
    v1 = client.CoreV1Api()
    resp = stream(
        v1.connect_get_namespaced_pod_exec,
        pod_name,
        namespace,
        command=command,
        stderr=True,
        stdin=False,
        stdout=True,
        tty=False,
        _preload_content=False,
    )
    while resp.is_open():
        resp.update(timeout=1)
        if resp.peek_stdout():
            click.echo(f"STDOUT: {resp.read_stdout()}")
        if resp.peek_stderr():
            click.echo(f"STDERR: {resp.read_stderr()}")

    resp.close()


def get_obj_by_key_value_from_list(
    key: str, value: JSONValue, obj_list: List[T], class_: Type[T]
) -> T:
    """
    Retrieves an object from a list based on a key-value pair.

    Args:
        key: The key to search for.
        value: The value to match.
        obj_list: The list of objects to search.  Must be a list of instances of `class_`.
        class_: The class of the objects in the list.  Used for type checking.

    Returns:
        The object matching the key-value pair, or raises an exception if not found.

    Raises:
        GetObjectByKeyValueError: If no object with the specified key-value pair is found.
        TypeError: if obj_list contains objects that are not instances of class_
    """
    for obj in obj_list:
        if not isinstance(obj, class_):
            raise TypeError(
                f"Object {obj} in list is not an instance of {class_.__name__}"
            )
        if getattr(obj, key) == value:
            return obj
    raise ValueError(f"No object found with key '{key}' and value '{value}'")


def extract_error_messages(exc: BaseException) -> Iterable[str]:
    while True:
        exc_str = str(exc).strip()
        yield f"{type(exc).__name__}: {exc_str}"
        opt_exc = exc.__cause__ or exc.__context__
        if not opt_exc:
            break

        exc = opt_exc


########################
#### Configurations ####
########################


class DEFAULT_SETTINGS:
    config_path: str = "./vault-config.yaml"
    output_path: str = "./output.json"
    url: str = "http://127.0.0.1:8200/"
    key_shares: int = 5
    threshold: int = 3
    instance_list: List[str] = ["vault-0", "vault-1", "vault-2"]
    namespace: str = "vault"
    port: int = 8200


class VaultPolicy(BaseModel):
    """Represents a policy for controlling access to Vault

    Attributes:
        name: The name of the policy. Must be unique
        rules: A string containing the policy rules in Vault's policy language (HCL)
    """

    name: str
    rules: str


class KubernetesAuthMethodConfigRole(BaseModel):
    """
    Represents a configuration role for Kubernetes authentication in HashiCorp Vault.

    Attributes:
        name (str): The name of the role to be configured.
        bound_service_account_names (List[str]): A list of Kubernetes service account names
            that are allowed to authenticate with this role.
        bound_service_account_namespaces (List[str]): A list of Kubernetes namespaces containing
            the service accounts that are bound to this role.
        policies (List[str]): A list of Vault policies to be applied to tokens issued via this role.
        ttl (str): The time-to-live (TTL) for tokens issued by this role. This is specified as a
            duration string, e.g., "1h" or "30m".
    """

    name: str
    bound_service_account_names: List[str]
    bound_service_account_namespaces: List[str]
    policies: List[str]
    ttl: str


class KubernetesAuthMethodConfig(BaseModel):
    """Configuration for Kubernetes authentication method in Vault.

    This class represents the configuration settings required to set up and manage
    Kubernetes authentication in HashiCorp Vault. It includes necessary credentials
    and connection details for Vault to authenticate against a Kubernetes cluster.

    Attributes:
        token_reviewer_jwt: Optional JWT token used by Vault to validate Kubernetes
            service account tokens. This token must have permissions to access the
            TokenReview API in the Kubernetes cluster.
        kubernetes_ca_cert: Optional PEM encoded CA certificate for the Kubernetes
            cluster. Used by Vault to verify the Kubernetes API server's TLS certificate.
        kubernetes_host: URL of the Kubernetes API server that Vault will connect to
            for authenticating service accounts (e.g., 'https://kubernetes.default.svc').
        roles: List of Kubernetes authentication roles configuration that map Kubernetes
            Service Accounts to Vault policies and tokens.
    """

    token_reviewer_jwt: Optional[str] = None
    kubernetes_ca_cert: Optional[str] = None
    kubernetes_host: str
    roles: List[KubernetesAuthMethodConfigRole]


class UserpassAuthMethodConfigUsers(BaseModel):
    """Configuration for individual users in Vault's Userpass authentication method.

    This class defines the credentials and permissions for users that can authenticate
    to Vault using username and password authentication.

    Attributes:
        username: The username that will be used for authentication to Vault.
        password: The password associated with the username for authentication.
        token_policies: List of Vault policies to be attached to tokens generated
            upon successful authentication of this user. These policies define the
            permissions the user will have in Vault.
    """

    username: str
    password: str
    token_policies: List[str]


class UserpassAuthMethodConfig(BaseModel):
    """Configuration for Userpass authentication method in Vault.

    This class represents the configuration for username/password authentication
    method in HashiCorp Vault. It allows setting up multiple users with their
    respective credentials and access policies.

    Attributes:
        users: List of user configurations, where each user entry contains
            their username, password, and associated token policies.
    """

    users: List[UserpassAuthMethodConfigUsers]


# TODO: Implement this
class TokenAuthMethodConfig(BaseModel):
    pass


class VaultAuthMethod(BaseModel):
    """Configuration for authentication methods in HashiCorp Vault.

    This class represents the configuration of an authentication method in Vault,
    defining how users or systems can authenticate to access Vault services.
    It supports multiple authentication types including Userpass, Token, and Kubernetes.

    Attributes:
        type: The type of authentication method to enable in Vault. Common values include
            'kubernetes', 'userpass', 'token', etc. This determines how credentials are
            validated.
        path: The path where the auth method will be mounted in Vault. For example,
            'kubernetes' for Kubernetes auth or 'userpass' for username/password auth.
            This path will be used in the Vault API URL: auth/<path>.
        method_config: Specific configuration for the chosen authentication method.
            Can be one of:
            - UserpassAuthMethodConfig for username/password authentication
            - TokenAuthMethodConfig for token-based authentication
            - KubernetesAuthMethodConfig for Kubernetes service account authentication
            If None, the auth method will be enabled with default settings.
    """

    type: str
    path: str
    method_config: Optional[
        Union[
            UserpassAuthMethodConfig, TokenAuthMethodConfig, KubernetesAuthMethodConfig
        ]
    ] = None


class VaultKVSecretEngine(BaseModel):
    """Configuration for Key-Value secret engine in Vault.

    This class defines the configuration for mounting and managing a Key-Value (KV)
    secrets engine in Vault. The KV secrets engine is used to store arbitrary secrets
    within the configured physical storage for Vault.

    Attributes:
        path: The path where the KV secrets engine will be mounted in Vault.
            For example, 'secret' or 'kv'. This path will be used to access
            secrets through the Vault API: <path>/data/...
        type: The type of the secrets engine. Should be either 'kv' or 'kv-v2'
            depending on the desired version of the KV secrets engine.
            - 'kv' is version 1 (no versioning)
            - 'kv-v2' is version 2 (includes versioning)
    """

    path: str
    type: str


class SyncSecret(BaseModel):
    """Configuration for synchronizing secrets into Vault.

    This class represents the configuration needed to create or update secrets
    in Vault's Key-Value store. It defines where and how secrets should be stored,
    including their location and content.

    Attributes:
        path: The path where the secret will be stored in Vault, relative to the
            mount point. For example, if you want to store a secret at
            'secret/myapp/credentials', the path would be 'myapp/credentials'.
        mount_point: The mount point of the secrets engine where the secret will
            be stored. This should match the 'path' configured in VaultKVSecretEngine.
            For example, 'secret' or 'kv'.
        type: The type of secret being stored. This should match the type of the
            secrets engine being used (e.g., 'kv' or 'kv-v2').
        data: A dictionary containing the secret data to be stored. Each key-value
            pair in this dictionary represents a field in the secret. For example:
            {
                "username": "admin",
                "password": "secret123",
                "api_key": "abcd1234"
            }
    """

    path: str
    mount_point: str
    type: str
    data: Dict


class Configuration(BaseModel):
    """Represents the overall configuration for Vault integration.

    This class encapsulates various aspects of Vault setup, including policies, authentication methods,
    secret engines, and startup secrets.  It serves as a central point for managing and accessing
    all configuration parameters related to Vault interaction within the application.

    Attributes:
        policies (List[VaultPolicy]): A list of Vault policies defining access control rules.
        auth (List[VaultAuthMethod]): A list of authentication methods configured for Vault.
        secret_engines (List[VaultKVSecretEngine]): A list of configured Key-Value secret engines in Vault.
        sync_secrets (List[SyncSecret]): A list of secrets that need to be retrieved during application startup.
    """

    policies: Optional[List[VaultPolicy]] = None
    auth: Optional[List[VaultAuthMethod]] = None
    secret_engines: Optional[List[VaultKVSecretEngine]] = None
    sync_secrets: Optional[List[SyncSecret]] = None


def load_config_file(config_path: str) -> Configuration:
    """Loads configuration from a YAML file.

    Args:
        config_path (str): The path to the YAML configuration file.  The path will be expanded
                        using `os.path.expanduser` to handle `~` for home directory.

    Returns:
        Configuration: A `Configuration` object populated with the data from the YAML file.
                    Returns an empty `Configuration` object if the file is empty or contains no valid YAML data.

    """
    try:
        with open(os.path.expanduser(config_path), "r") as f:
            config = yaml.safe_load(f) or {}
            return Configuration(**config)
    except FileNotFoundError:
        raise click.ClickException(f"No config file at {config_path}.")
    except IOError:
        raise click.ClickException(
            f"Config file exists at {config_path}, but cannot be read. "
            "Have you checked permission?"
        )


################
#### Client ####
################


@contextlib.contextmanager
def handle_client_errors():
    try:
        yield
    except client_exception.InvalidRequest as exc:
        raise VaultInvalidRequest(errors=exc.errors) from exc
    except client_exception.Unauthorized as exc:
        raise VaultUnauthorized(errors=exc.errors) from exc
    except client_exception.Forbidden as exc:
        raise VaultForbidden(errors=exc.errors) from exc
    except client_exception.InternalServerError as exc:
        raise VaultInternalServerError(errors=exc.errors) from exc
    except client_exception.VaultDown as exc:
        raise VaultSealed(errors=exc.errors) from exc
    except client_exception.UnexpectedError as exc:
        raise VaultAPIException(errors=exc.errors) from exc
    except client_exception.VaultNotInitialized as exc:
        raise VaultNotInitialized() from exc
    except requests.exceptions.ConnectionError as exc:
        raise VaultConnectionError() from exc


class VaultClient:
    def __init__(
        self,
        url: str = DEFAULT_SETTINGS.url,
    ) -> None:
        self.url = url
        self.errors: List[str] = []
        self.client = hvac.Client(url=self.url)

    def auth(
        self,
        token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        if token:
            self.client.token = token
        elif username:
            if not password:
                raise VaultAuthenticationError("Cannot use username without password")
            self.client.auth.userpass.login(username=username, password=password)
        else:
            raise VaultAuthenticationError("No authentication method supplied")

    @handle_client_errors()
    def is_initialized(self) -> bool:
        """Determine is Vault is initialized or not."""
        return self.client.sys.is_initialized()

    @handle_client_errors()
    def is_sealed(self) -> bool:
        """Determine if  Vault is sealed."""
        return self.client.sys.is_sealed()

    @handle_client_errors()
    def health_status(self) -> JSONDict:
        """Read the health status of Vault."""
        return self.client.sys.read_health_status(method="GET")

    @handle_client_errors()
    def seal_status(self) -> Dict:
        """Read the seal status of the Vault."""
        return self.client.sys.read_seal_status()

    @handle_client_errors()
    def initialize(self, shares: int, threshold: int) -> JSONDict:
        """Initialize a new Vault."""
        return self.client.sys.initialize(shares, threshold)

    @handle_client_errors()
    def unseal_keys(self, keys) -> JSONDict:
        """Enter multiple master keys share to progress the unsealing of Vault"""
        return self.client.sys.submit_unseal_keys(keys=keys)

    @handle_client_errors()
    def auth_methods_list(self) -> JSONDict:
        """List all enabled auth methods."""
        return self.client.sys.list_auth_methods().get("data", {})

    @handle_client_errors()
    def auth_method_enable(self, method_type: str, path: str) -> JSONDict:
        """Enable a new auth method."""
        return self.client.sys.enable_auth_method(method_type=method_type, path=path)

    @handle_client_errors()
    def auth_method_disable(self, path: str) -> JSONDict:
        """Disable the auth method at the given auth path."""
        return self.client.sys.disable_auth_method(path=path)

    @handle_client_errors()
    def kubernetes_auth_method_configure(
        self, kubernetes_host: str, **kwargs
    ) -> JSONDict:
        """Configure the connection parameters for Kubernetes."""
        return self.client.auth.kubernetes.configure(
            kubernetes_host=kubernetes_host, **kwargs
        )

    @handle_client_errors()
    def kubernetes_auth_method_read_config(
        self, mount_point: str, name: str
    ) -> JSONDict:
        """Return the previously configured config, including credentials."""
        return self.client.auth.kubernetes.read_config(
            mount_point=mount_point, name=name
        )

    @handle_client_errors()
    def kubernetes_auth_method_list_role(self, mount_point: str) -> List:
        """List all the roles that are registered with the plugin."""
        # This behavior might be a bug or an undefined behavior in the Vault Client.
        # When attempting to list roles on an empty mount_point (no roles exist),
        # the client raises an InvalidPath exception.
        # This causes errors in subsequent operations, such as creating new roles
        # or updating existing roles based on the current list of roles.
        #
        # Workaround:
        # We catch the InvalidPath exception and return an empty list.
        # This ensures that subsequent steps for role creation or updates
        # can proceed without issues.
        try:
            roles = self.client.auth.kubernetes.list_roles(mount_point=mount_point)
        except client_exception.InvalidPath:
            return []
        return roles.get("keys", [])

    @handle_client_errors()
    def kubernetes_auth_method_read_role(self, mount_point: str, name: str) -> JSONDict:
        """Returns the previously registered role configuration."""
        role = self.client.auth.kubernetes.read_role(mount_point=mount_point, name=name)
        role_info: Dict = {
            "name": name,
            "bound_service_account_names": role["bound_service_account_names"],
            "bound_service_account_namespaces": role[
                "bound_service_account_namespaces"
            ],
            "policies": role["policies"],
            "ttl": role["ttl"],
        }

        return role_info

    @handle_client_errors()
    def kubernetes_auth_method_create_role(
        self,
        mount_point: str,
        name: str,
        bound_service_account_names: List[str],
        bound_service_account_namespaces: List[str],
        ttl: str,
        policies: List[str],
        **kwargs,
    ) -> JSONDict:
        """Create a role in the method."""
        return self.client.auth.kubernetes.create_role(
            mount_point=mount_point,
            name=name,
            bound_service_account_names=bound_service_account_names,
            bound_service_account_namespaces=bound_service_account_namespaces,
            ttl=ttl,
            policies=policies,
            **kwargs,
        )

    @handle_client_errors()
    def kubernetes_auth_method_delete_role(
        self, mount_point: str, name: str
    ) -> JSONDict:
        """Delete the previously registered role."""
        return self.client.auth.kubernetes.delete_role(
            mount_point=mount_point, name=name
        )

    @handle_client_errors()
    def userpass_auth_method_create_or_update_user(
        self,
        username: str,
        password: str,
        policies: List[str],
        mount_point: str,
        **kwargs,
    ) -> JSONDict:
        """Create/update user in userpass."""
        return self.client.auth.userpass.create_or_update_user(
            username=username,
            password=password,
            policies=policies,
            mount_point=mount_point,
            **kwargs,
        )

    @handle_client_errors()
    def userpass_auth_method_list_user(self, mount_point: str) -> List[str]:
        """List existing users that have been created in the auth method."""
        # Similar as Kubernetes authenticate methods, it will raise exception
        # when list to empty mount_point
        try:
            users = self.client.auth.userpass.list_user(mount_point=mount_point)
        except client_exception.InvalidPath:
            return []

        return users["data"]["keys"]

    @handle_client_errors()
    def userpass_auth_method_read_user(
        self, username: str, mount_point: str
    ) -> JSONDict:
        """Read user in the auth method."""
        user = self.client.auth.userpass.read_user(
            username=username, mount_point=mount_point
        )
        user_info: JSONDict = {
            "username": username,
            "token_policies": user["data"]["token_policies"],
        }
        return user_info

    @handle_client_errors()
    def userpass_auth_method_update_password_on_user(self):
        """Update password for the user in userpass."""
        pass

    @handle_client_errors()
    def userpass_auth_method_delete_user(
        self, username: str, mount_point: str
    ) -> JSONDict:
        """Delete the user in the auth method."""
        return self.client.auth.userpass.delete_user(
            mount_point=mount_point, username=username
        )

    @handle_client_errors()
    def policy_list(self) -> List:
        """List all configured policies."""
        return self.client.sys.list_policies().get("policies") or []

    @handle_client_errors()
    def policy_read(self, name: str) -> JSONDict:
        """Retrieve the policy body for the named policy."""
        return self.client.sys.read_policy(name=name)

    @handle_client_errors()
    def policy_create_or_update(
        self, name: str, policy: Union[str, Dict], pretty_print: bool = True
    ) -> Dict[str, JSONValue]:
        """Add a new or update an existing policy."""
        return self.client.sys.create_or_update_policy(
            name=name, policy=policy, pretty_print=pretty_print
        )

    @handle_client_errors()
    def policy_delete(self, name: str) -> JSONDict:
        """Delete the policy with the given name."""
        return self.client.sys.delete_policy(name=name)

    @handle_client_errors()
    def kvv2_secrets_engines_list(self) -> JSONDict:
        """Lists all the mounted secrets engines."""
        return self.client.sys.list_mounted_secrets_engines().get("data") or {}

    @handle_client_errors()
    def kvv2_secrets_engines_enable(self, path: str, **kwargs) -> JSONDict:
        return self.client.sys.enable_secrets_engine(
            backend_type="kv",
            path=path,
            options={"version": "2"},
        )

    @handle_client_errors()
    def kvv2_secrets_engines_disable(self, path: str) -> JSONDict:
        return self.client.sys.disable_secrets_engine(path=path)

    @handle_client_errors()
    def kvv2_secrets_list(self, path: str, mount_point: str) -> List:
        return (
            self.client.secrets.kv.v2.list_secrets(path=path, mount_point=mount_point)[
                "data"
            ]["keys"]
            or []
        )

    @handle_client_errors()
    def kvv2_secrets_read(self, path: str, mount_point: str) -> JSONDict:
        return (
            self.client.secrets.kv.v2.read_secret(path=path, mount_point=mount_point)[
                "data"
            ]
            or {}
        )

    @handle_client_errors()
    def kvv2_secrets_create_or_update(self, path: str, secret: Dict, mount_point: str):
        return self.client.secrets.kv.v2.create_or_update_secret(
            path=path, secret=secret, mount_point=mount_point
        )


#################
#### Command ####
#################


def print_version(ctx, __, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo("v0.1.0")
    ctx.exit()


class Commands:
    def __init__(self, client: VaultClient) -> None:
        self.client = client

    def create_vault(
        self, output_path: str, key_shares: int, threshold: int
    ) -> Tuple[List, str]:
        """Creates a vault and saves the keys and root token to a file.

        Args:
            output_path: The path to save the vault keys and root token.
            key_shares: The number of key shares to generate.
            threshold: The minimum number of key shares required to unlock the vault.

        Returns:
            A tuple containing a list of keys and the root token.  Returns empty list and empty string if the client is already initialized.

        Raises:
            Exception: If there is an error creating the vault.
        """

        try:
            result: Dict[str, Any] = self.client.initialize(key_shares, threshold)
            keys: List[Dict[str, Any]] = result["keys"]
            root_token: str = result["root_token"]

            # Save output of initialize step (unseal keys and root_token)
            with open(output_path, "w") as f:
                json.dump(result, f, indent=4)

            return keys, root_token

        except Exception as e:
            raise Exception(f"Error creating vault: {e}") from e

    def unseal_instances(
        self,
        keys: list,
        instance_list: list,
        namespace: str,
        port: int,
    ) -> None:
        """Unseals multiple instances within a specified namespace using a set of provided keys.

        Iterates through a list of instances and calls `unseal_instance` for each one.

        Args:
            keys: A list of keys required to unseal the instances.  If empty, defaults to using any available keys.
            instance_list: A list of instance names to unseal.  Each name should correspond to an instance that exists within the specified namespace.
            namespace: The namespace containing the instances to unseal. Defaults to "vault".
        """

        # The unseal process for Vault must be performed on the leader node –
        # the node that initialized Vault first. After that, the other nodes
        # can proceed to unseal Vault.”
        click.echo("Unsealing the leader node...")
        self.client.unseal_keys(keys=keys)
        click.echo("Leader is unseal successfully!")

        # Note: Unsealing a node that is already unsealed is allowed and will not cause issues.
        # Currently, there is no implemented logic to handle this duplicate operation.
        # Contributions and suggestions to improve this are welcome!
        for instance in instance_list:
            count = 1
            for key in keys:
                operator = f"vault operator unseal --address http://{instance}:{port}"
                command = ["/bin/sh", "-c", f"{operator} {key}"]
                execute_command_in_pod(
                    pod_name=instance,
                    namespace=namespace,
                    command=command,
                )
                click.echo(f"Unseal instance: {instance} - {count}/{len(keys)}")
                count += 1
                time.sleep(2)  # Sleep between each time unseal

            click.echo(f"Unseal instace: {instance} successfully!")

    def sync_policy(
        self, policies: Optional[List] = None, remove_orphans: bool = False
    ):
        """Sync policies from configurations to Vault.

        Args:
            policies: A list of policies from the configurations.
            remove_orphan: A boolean indicating whether to remove orphan policies from Vault.

        Returns:
            A list of strings representing any errors encountered during the sync process.  Returns an empty list if successful.
        """
        errors = []
        # Check if policies configurations exists
        if not policies:
            return errors

        # Sync policies configurations
        try:
            # Get Policies from Vault
            exclude_policies = ["root", "default"]
            vault_policies = set(
                [
                    name
                    for name in self.client.policy_list()
                    if (name not in exclude_policies)
                ]
            )
            # Get policies from configurations
            config_policies = set([policy.name for policy in policies])

            # Compare and sync
            ## Policies present in config but not in Vault
            policies_to_create = config_policies - vault_policies
            ## Policies present in both config and vault
            policies_to_update = config_policies.intersection(vault_policies)
            ## Policies present in Vault but not in config
            policies_to_remove = vault_policies - config_policies

            # Create new policies
            for name in policies_to_create:
                try:
                    self.client.policy_create_or_update(
                        name=name,
                        policy=get_obj_by_key_value_from_list(
                            key="name",
                            value=name,
                            obj_list=policies,
                            class_=VaultPolicy,
                        ).rules,
                    )
                except Exception as exc:
                    errors.append(f"Error creating policy '{name}: {exc}")

            # Update existing policies
            for name in policies_to_update:
                try:
                    config_policy_rules = get_obj_by_key_value_from_list(
                        key="name", value=name, obj_list=policies, class_=VaultPolicy
                    ).rules
                    vault_policy_rules = self.client.policy_read(name=name)
                    if config_policy_rules != vault_policy_rules:
                        self.client.policy_create_or_update(
                            name=name, policy=config_policy_rules
                        )

                except Exception as e:
                    errors.append(f"Error updating policy '{name}': {e}")

            # Remove orphan policies
            if remove_orphans:
                for name in policies_to_remove:
                    try:
                        self.client.policy_delete(name)
                    except Exception as e:
                        errors.append(f"Error removing policy '{name}': {e}")
            elif policies_to_remove:
                click.echo(
                    f"Warning: Orphan policies '{policies_to_remove}'."
                    "\nThese following policy exist in Vault but are no longer defined in the configurations."
                    "\nYou can run 'sync_config --remove_orphans' to delete them."
                )

        except Exception as exc:
            errors.append(f"An unexpected error occurred: {exc}")

        return errors

    def sync_authmethods(
        self, authmethods: Optional[List] = None, remove_orphans: bool = False
    ) -> List:
        errors = []
        # Check if Authentication methods configurations exists
        if not authmethods:
            return errors

        # Sync authenticate methods configurations
        try:
            # Get Authentication methods from Vault
            vault_authmethods = [
                {"path": path, "type": details["type"]}
                for path, details in self.client.auth_methods_list().items()
                if isinstance(details, dict) and "type" in details
            ]

            # List Authentication methods from configurations
            config_authmethods = [
                {"path": c_am.path, "type": c_am.type} for c_am in authmethods
            ]

            authmethod_to_enable = [
                method
                for method in config_authmethods
                if method not in vault_authmethods
            ]
            authmethod_to_disable = [
                method
                for method in vault_authmethods
                if method not in config_authmethods
            ]

            for method in authmethod_to_enable:
                try:
                    self.client.auth_method_enable(
                        method_type=method["type"], path=method["path"]
                    )
                except Exception as exc:
                    errors.append(
                        f"Error enable authentication method, type {method['type']} in path {method['path']}: {exc}"
                    )

            if remove_orphans:
                for method in authmethod_to_disable:
                    try:
                        self.client.auth_method_disable(path=method["path"])
                    except Exception as exc:
                        errors.append(
                            f"Error disable authentication method, type {method['type']} in path {method['path']}: {exc}"
                        )
            elif authmethod_to_disable:
                click.echo(
                    f"Warning: Orphan authentication method '{authmethod_to_disable}'."
                    "\nThese following authentication method still enabled in Vault but are no longer defined in the configurations."
                    "\nYou can run 'sync_configs --remove_orphans' to delete them."
                )

            for method in authmethods:
                if method.type == "kubernetes":
                    self._sync_kubernetes_authmethod_config(
                        config=method.method_config,
                        mount_point=method.path,
                        errors=errors,
                        remove_orphans=remove_orphans,
                    )
                elif method.type == "userpass":
                    self._sync_userpass_authmethod_config(
                        config=method.method_config,
                        mount_point=method.path,
                        errors=errors,
                        remove_orphans=remove_orphans,
                    )
                elif method.type == "token":
                    self._sync_token_authmethod_config(method.method_config)

        except Exception as exc:
            errors.append(f"An unexpected error occurred: {exc}")

        return errors

    def _sync_kubernetes_authmethod_config(
        self,
        config: KubernetesAuthMethodConfig,
        mount_point: str,
        errors: List,
        remove_orphans: bool,
    ) -> None:
        try:
            # TODO: Add config token_reviewer_jwt, kubernetes_ca_cert to kwargs
            self.client.kubernetes_auth_method_configure(
                config.kubernetes_host
            )  # Sync configs

            # Sync roles
            ## List roles from Vault
            vault_roles = set(
                self.client.kubernetes_auth_method_list_role(mount_point=mount_point)
            )

            ## List roles from configs
            config_roles = set([role.name for role in config.roles])

            # Compare
            roles_to_create = config_roles - vault_roles
            roles_to_update = config_roles.intersection(vault_roles)
            roles_to_delete = vault_roles - config_roles

            # Create new role
            for role in roles_to_create:
                try:
                    role_data = get_obj_by_key_value_from_list(
                        key="name",
                        value=role,
                        obj_list=config.roles,
                        class_=KubernetesAuthMethodConfigRole,
                    )
                    self.client.kubernetes_auth_method_create_role(
                        mount_point=mount_point,
                        name=role,
                        bound_service_account_names=role_data.bound_service_account_names,
                        bound_service_account_namespaces=role_data.bound_service_account_namespaces,
                        ttl=role_data.ttl,
                        policies=role_data.policies,
                    )
                except Exception as exc:
                    errors.append(f"Error creating role {role}: {exc}")

            # Update existing role if changed
            for role in roles_to_update:
                try:
                    # Read role configs from Vault and compare
                    from_vault = self.client.kubernetes_auth_method_read_role(
                        name=role, mount_point=mount_point
                    )
                    from_config = get_obj_by_key_value_from_list(
                        key="name",
                        value=role,
                        obj_list=config.roles,
                        class_=KubernetesAuthMethodConfigRole,
                    )
                    if from_config.__dict__ != from_vault:
                        self.client.kubernetes_auth_method_create_role(
                            mount_point=mount_point,
                            name=role,
                            bound_service_account_names=from_config.bound_service_account_names,
                            bound_service_account_namespaces=from_config.bound_service_account_namespaces,
                            ttl=from_config.ttl,
                            policies=from_config.policies,
                        )

                except Exception as exc:
                    errors.append(f"Error updating role {role}: {exc}")

            if remove_orphans:
                for role in roles_to_delete:
                    try:
                        self.client.kubernetes_auth_method_delete_role(
                            mount_point=mount_point, name=role
                        )
                    except Exception as exc:
                        errors.append(f"Error removing role {role}: {exc}")
            elif roles_to_delete:
                click.echo(
                    f"Warning: Orphan Kubernetes authentication method roles '{roles_to_delete}'."
                    "\nThese following role exist in Vault but are no longer defined in the configurations."
                    "\nYou can run 'sync_config --remove_orphans' to delete them."
                )

        except VaultException as exc:
            errors.append(
                f"An unexpected error occurred when sync kubernetes authentication method: {exc}"
            )

    def _sync_userpass_authmethod_config(
        self,
        config: UserpassAuthMethodConfig,
        mount_point: str,
        errors: List,
        remove_orphans: bool,
    ) -> None:
        try:
            # List users from Vault
            vault_users = set(
                self.client.userpass_auth_method_list_user(mount_point=mount_point)
            )
            # List user from configs
            config_users = set([user.username for user in config.users])

            # Compare
            users_to_create = config_users - vault_users
            users_to_update = config_users.intersection(vault_users)
            users_to_delete = vault_users - config_users

            # Create new users
            for user in users_to_create:
                try:
                    user_data = get_obj_by_key_value_from_list(
                        key="username",
                        value=user,
                        obj_list=config.users,
                        class_=UserpassAuthMethodConfigUsers,
                    )
                    self.client.userpass_auth_method_create_or_update_user(
                        username=user,
                        password=user_data.password,
                        mount_point=mount_point,
                        policies=user_data.token_policies,
                    )
                except Exception as exc:
                    errors.append(f"Error creating user {user}: {exc}")

            # Update existing users if changed
            for user in users_to_update:
                try:
                    from_vault = self.client.userpass_auth_method_read_user(
                        username=user, mount_point=mount_point
                    )
                    from_config = get_obj_by_key_value_from_list(
                        key="username",
                        value=user,
                        obj_list=config.users,
                        class_=UserpassAuthMethodConfigUsers,
                    )
                    # Because user information from Vault not have password field, so we need to remove it
                    # from config to compare. After compare, if user need update, we add password to request
                    # to ensure password always latest version from config
                    password_defined = from_config.password
                    from_config.__dict__.pop("password")
                    if (
                        from_config.__dict__["token_policies"]
                        != from_vault["token_policies"]
                    ):
                        self.client.userpass_auth_method_create_or_update_user(
                            username=user,
                            password=password_defined,
                            policies=from_config.token_policies,
                            mount_point=mount_point,
                        )
                except Exception as exc:
                    errors.append(f"Error updating user {user}: {exc}")

            # Delete users
            if remove_orphans:
                for user in users_to_delete:
                    try:
                        self.client.userpass_auth_method_delete_user(
                            username=user, mount_point=mount_point
                        )
                    except Exception as exc:
                        errors.append(f"Error removing user {user}: {exc}")
            elif users_to_delete:
                click.echo(
                    f"Warning: Orphan Userpass authentication method users '{users_to_delete}'."
                    "\nThese following users exist in Vault but are no longer defined in the configurations."
                    "\nYou can run 'sync_config --remove_orphans' to delete them."
                )

        except VaultException as exc:
            errors.append(f"An unexpected error occurred: {exc}")

    # TODO: Implement this
    def _sync_token_authmethod_config(self, config: TokenAuthMethodConfig):
        pass

    def sync_kvv2_secretengines(
        self,
        secrets_engines: Optional[List[VaultKVSecretEngine]] = None,
        remove_orphans: bool = False,
    ) -> List:
        errors = []

        if not secrets_engines:
            return errors

        try:
            # Get list kvv2 secrets engines mount and exclude default mounts
            mounts_vault = set(
                [path for path in self.client.kvv2_secrets_engines_list().keys()]
            ) - set(["cubbyhole/", "identity/", "sys/"])

            # Get from config
            mounts_config = set([mount.path for mount in secrets_engines])

            # Compare
            mounts_to_create = mounts_config - mounts_vault
            mounts_to_disable = mounts_vault - mounts_config

            # Enable secrets engines path
            for mount in mounts_to_create:
                try:
                    self.client.kvv2_secrets_engines_enable(path=mount)
                except Exception as exc:
                    errors.append(
                        f"Error enable secrets engines, type kv-v2 in path {mount}: {exc}"
                    )

            if remove_orphans:
                for mount in mounts_to_disable:
                    try:
                        self.client.kvv2_secrets_engines_disable(path=mount)
                    except Exception as exc:
                        errors.append(
                            f"Error disable secrets engines, type kv-v2 in path {mount}: {exc}"
                        )
            elif mounts_to_disable:
                click.echo(
                    f"Warning: Orphan secrets engines mounts '{mounts_to_disable}'."
                    "\nThese following secrets engines still enabled in Vault but are no longer defined in the configurations."
                    "\nYou can run 'sync_configs --remove_orphans' to delete them."
                )

        except Exception as exc:
            errors.append(f"An unexpected error occurred: {exc}")

        return errors

    def sync_secrets(
        self, sync_secrets: Optional[List] = None, remove_orphans: bool = False
    ) -> List:
        errors = []
        if not sync_secrets:
            return errors

        try:
            for secret in sync_secrets:
                self.client.kvv2_secrets_create_or_update(
                    path=secret.path, mount_point=secret.mount_point, secret=secret.data
                )

        except Exception as exc:
            errors.append(f"An unexpected error occurred: {exc}")

        return errors


@contextlib.contextmanager
def handle_errors():
    try:
        yield
    except VaultException as exc:
        raise click.ClickException("\n".join(extract_error_messages(exc)))


CONTEXT_SETTINGS = {
    "help_option_names": ["-h", "--help"],
}


class CLIContext:
    client: VaultClient
    cfg: Configuration

    def __init__(self, client: VaultClient, cfg: Configuration) -> None:
        self.client = client
        self.cfg = cfg


@click.group(context_settings=CONTEXT_SETTINGS)
@click.pass_context
@click.option(
    "--config_path",
    "-c",
    help="Path to configuration file",
    default=DEFAULT_SETTINGS.config_path,
    show_default=True,
)
@click.option(
    "--url",
    "-u",
    default=DEFAULT_SETTINGS.url,
    show_default=True,
    help="URL of the Vault instance.",
)
@click.option(
    "-V",
    "--version",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
)
@handle_errors()
def cli(ctx: click.Context, config_path: str, url: str) -> None:
    """
    Interact with a Vault. See subcommands for details.

    All arguments can be passed by environment variables: VAULT_CLI_UPPERCASE_NAME
    (including VAULT_CLI_PASSWORD and VAULT_CLI_TOKEN).

    """
    ctx.ensure_object(dict)
    ctx.obj = CLIContext(VaultClient(url=url), load_config_file(config_path))


@cli.command()
@click.pass_obj
@click.option(
    "--output_path",
    "-o",
    default=DEFAULT_SETTINGS.output_path,
    show_default=True,
    help="Path to the file where content like root token and unseal key from the initialization step is saved.",
)
@click.option(
    "--key_shares",
    "-n",
    default=DEFAULT_SETTINGS.key_shares,
    help="Number of keys that Vault will create during the initialization step.",
)
@click.option(
    "--threshold",
    "-t",
    default=DEFAULT_SETTINGS.threshold,
    help="Number of keys required to unseal Vault.",
)
@click.option(
    "--instance_list",
    help="List of Vault instance name that used to unseal.",
    multiple=True,
    default=DEFAULT_SETTINGS.instance_list,
    show_default=True,
)
@click.option(
    "--namespace",
    default=DEFAULT_SETTINGS.namespace,
    show_default=True,
    help="Kubernetes namespace that install Vault.",
)
@click.option(
    "--port",
    default=DEFAULT_SETTINGS.port,
    show_default=True,
    help="Kubernetes port that install Vault.",
)
@handle_errors()
def bootstrap(
    ctx: CLIContext,
    output_path: str,
    key_shares: int,
    threshold: int,
    instance_list: Tuple,
    namespace: str,
    port: int,
) -> None:
    """
    Bootstrap the target Vault cluster

    This command will verify the configurations, run "vault init" against the target Vault instance,
    before storing the token, keys in the given output path.

    After initializing, it will unseal the Vault cluster and apply the predefined configurations.
    """
    # Create raw Vault client
    commands = Commands(ctx.client)

    # Check Vault initialized
    click.echo("Checking Vault...")
    initialized = ctx.client.is_initialized()
    if initialized:
        click.echo("Your Vault is initialized, do your next action.")
        return

    # Initialize Vault
    click.echo("Vault initializing...")
    keys, root_token = commands.create_vault(
        output_path=output_path,
        key_shares=key_shares,
        threshold=threshold,
    )
    click.echo("Vault initialized.")

    # Wait for Cluster initialized
    time.sleep(10)

    # Unseal Vault
    click.echo("Vault unsealing...")
    commands.unseal_instances(
        keys=keys[:threshold],  # We only need "threshold" number of key to unseal
        instance_list=list(instance_list),
        namespace=namespace,
        port=port,
    )

    # Authenticate with Vault
    ctx.client.auth(token=root_token)

    errors = []
    # Apply predefined configurations
    click.echo("Vault configurations syncing...")
    errors.extend(commands.sync_policy(ctx.cfg.policies))
    errors.extend(commands.sync_authmethods(ctx.cfg.auth))
    errors.extend(commands.sync_kvv2_secretengines(ctx.cfg.secret_engines))
    click.echo("Vault configurations synced.")
    # Sync secrets
    click.echo("Vault secrets syncing.")
    errors.extend(commands.sync_secrets(ctx.cfg.sync_secrets))
    click.echo("Vault secrets synced.")

    if errors:
        for err in errors:
            click.echo(err)
    else:
        click.echo("Your vault is ready. Let's go! :D")


@cli.command()
@click.pass_obj
@click.option(
    "--instance_list",
    help="List of Vault instance name that used to unseal.",
    multiple=True,
    default=DEFAULT_SETTINGS.instance_list,
    show_default=True,
)
@click.option(
    "--namespace",
    default=DEFAULT_SETTINGS.namespace,
    show_default=True,
    help="Kubernetes namespace that install Vault.",
)
@click.option(
    "--port",
    default=DEFAULT_SETTINGS.port,
    show_default=True,
    help="Kubernetes port that install Vault.",
)
@handle_errors()
def unseal(
    ctx: CLIContext,
    instance_list: Tuple,
    namespace: str,
    port: int,
) -> None:
    """
    Unseals Vault with unseal keys provide from command line.

    It will continuously attempt to unseal the target Vault instance, by retrieving unseal keys
    from command line.
    """
    # Check seal status
    status = ctx.client.seal_status()
    if not status.get("sealed"):
        click.echo("Your Vault is not sealed.")
        return
    # Get threshold of Vault
    threshold = int(status.get("t", 0))
    keys: List[str] = []
    for i in range(threshold):
        key = click.prompt(f"Enter the unseal key {i}: ", type=str)
        keys.append(key)

    commands = Commands(ctx.client)
    click.echo("Vault unsealing...")
    commands.unseal_instances(
        keys=keys,
        namespace=namespace,
        instance_list=list(instance_list),
        port=port,
    )

    click.echo("Unseal progress done. Let's take a coffee. :3")


@cli.command()
@click.pass_obj
@click.option(
    "--token",
    prompt=True,
    hide_input=True,
    prompt_required=False,
    envvar="VAULT_CLI_TOKEN",
    help="Token to connect to Vault.",
)
@click.option(
    "--username",
    "-U",
    prompt=True,
    prompt_required=False,
    envvar="VAULT_CLI_USERNAME",
    help="Username used for userpass authentication.",
)
@click.option(
    "--password",
    "-w",
    prompt=True,
    hide_input=True,
    prompt_required=False,
    envvar="VAULT_CLI_PASSWORD",
    help="Password used for userpass authentication.",
)
@click.option(
    "--remove_orphans",
    "-ro",
    help="Remove orphans data",
    is_flag=True,
    default=False,
    show_default=True,
)
@handle_errors()
def sync_configs(
    ctx: CLIContext, token: str, username: str, password: str, remove_orphans: bool
):
    """Synchronizes configurations from a file to Vault.

    Reads configuration data from the file specified by `CONFIG_FILE_PATH` (an environment variable or configuration setting),
    and pushes this data to the Vault server.
    """
    # Client Authentication
    ctx.client.auth(
        token=token,
        username=username,
        password=password,
    )
    errors = []
    commands = Commands(ctx.client)

    # Sync Vault configurations
    errors.extend(commands.sync_policy(ctx.cfg.policies, remove_orphans))
    errors.extend(commands.sync_authmethods(ctx.cfg.auth, remove_orphans))
    errors.extend(
        commands.sync_kvv2_secretengines(ctx.cfg.secret_engines, remove_orphans)
    )

    if errors:
        for err in errors:
            click.echo(err)
    else:
        click.echo("All configurations is synced. Feel happy. ^^")


@cli.command()
@click.pass_obj
@click.option(
    "--token",
    prompt=True,
    hide_input=True,
    prompt_required=False,
    envvar="VAULT_CLI_TOKEN",
    help="Token to connect to Vault.",
)
@click.option(
    "--username",
    "-U",
    prompt=True,
    prompt_required=False,
    envvar="VAULT_CLI_USERNAME",
    help="Username used for userpass authentication.",
)
@click.option(
    "--password",
    "-w",
    prompt=True,
    hide_input=True,
    prompt_required=False,
    envvar="VAULT_CLI_PASSWORD",
    help="Password used for userpass authentication.",
)
@click.option(
    "--remove_orphans",
    "-ro",
    help="Remove orphans data",
    is_flag=True,
    default=False,
    show_default=True,
)
@handle_errors()
def sync_secrets(
    ctx: CLIContext, token: str, username: str, password: str, remove_orphans: bool
):
    """Synchronizes secrets from a file to Vault.

    Reads secrets data from the file specified by `CONFIG_FILE_PATH` (an environment variable or configuration setting),
    and pushes this data to the Vault server.
    """
    # Client Authentication
    ctx.client.auth(
        token=token,
        username=username,
        password=password,
    )
    commands = Commands(ctx.client)
    errors = commands.sync_secrets(ctx.cfg.sync_secrets, remove_orphans)

    if errors:
        for err in errors:
            click.echo(err)
    else:
        click.echo("Secrets is synced. Feel happy ^^!")


##############
#### Main ####
##############


def main():
    """Main function to parse arguments and run the application."""
    cli()


if __name__ == "__main__":
    main()
