import contextlib
import json
import os
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Type, TypeVar, Union

import click
import hvac
import hvac.exceptions as client_exception
import requests
import yaml
from kubernetes import client, config
from kubernetes.stream import stream
from pydantic import BaseModel

# from rich.progress import (
#     Progress,
#     SpinnerColumn,
#     TextColumn,
# )


################
#### Typing ####
################

JSONValue = Union[str, int, float, bool, None, Dict[str, Any], List[Any]]
JSONDict = Dict[str, JSONValue]
T = TypeVar("T")

###################
#### Utilities ####
###################


def path_to_nested(dict_obj: Dict) -> Dict:
    """
    Transform a dict with paths as keys into a nested
    dict
    >>> path_to_nested ({"a/b/c": "d", "a/e": "f"})
    {"a": {"b": {"c": "d"}, "e": "f"}}

    If 2 unconsistent values are detected, fails with ValueError:
    >>> path_to_nested ({"a/b/c": "d", "a/b": "e"})
    ValueError()
    """

    for path in list(dict_obj):
        working_dict = dict_obj

        value = dict_obj.pop(path)

        *folders, subpath = path.strip("/").split("/")

        for folder in folders:
            sub_dict = working_dict.setdefault(folder, {})
            if not isinstance(sub_dict, dict):
                raise ValueError("Inconsistent values detected")
            working_dict = sub_dict

        if subpath in working_dict:
            raise ValueError("Inconsistent values detected")
        working_dict[subpath] = value
    return dict_obj


def execute_command_in_pod(pod_name, namespace, command):
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
    raise Exception(f"No object found with key '{key}' and value '{value}'")


########################
#### Configurations ####
########################


class Setting(BaseModel):
    """Base configurations use by cli tool to do it job

    Attributes:
        config_path: Path to the configuration file.
        output_path: Path to the file where content like root token and unseal key from the initialization step is saved.
        url (str): URL of the Vault instance.
        url: URL of the Vault instance.
        key_shares: Number of keys that Vault will create during the initialization step.
        threshold: Number of keys required to unseal Vault.
        instance_list: List of Vault instance name.
        namespace: Kubernetes namespace where Vault is installed.
        username: Username to access Vault.
        password: Password to access Vault.
        token: Token to access Vault.
    """

    config_path: str = "./vault-config.yaml"
    output_path: str = "./output.json"
    url: str = "http://127.0.0.1:8200/"
    key_shares: int = 5
    threshold: int = 3
    instance_list: List[str] = ["vault-0", "vault-1", "vault-2"]
    namespace: str = "vault"
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None


DEFAULT_SETTINGS = Setting()


class VaultPolicy(BaseModel):
    """[TODO:description]

    Attributes:
        name: [TODO:attribute]
        rules: [TODO:attribute]
    """

    name: str
    rules: str


class KubernetesAuthMethodConfigRole(BaseModel):
    """[TODO:description]

    Attributes:
        name: [TODO:attribute]
        bound_service_account_names: [TODO:attribute]
        bound_service_account_namespaces: [TODO:attribute]
        policies: [TODO:attribute]
        ttl: [TODO:attribute]
    """

    name: str
    bound_service_account_names: List[str]
    bound_service_account_namespaces: List[str]
    policies: List[str]
    ttl: str


class KubernetesAuthMethodConfig(BaseModel):
    """[TODO:description]

    Attributes:
        token_reviewer_jwt: [TODO:attribute]
        kubernetes_ca_cert: [TODO:attribute]
        kubernetes_host: [TODO:attribute]
        roles: [TODO:attribute]
    """

    token_reviewer_jwt: Optional[str] = None
    kubernetes_ca_cert: Optional[str] = None
    kubernetes_host: str
    roles: List[KubernetesAuthMethodConfigRole]


class UserpassAuthMethodConfigUsers(BaseModel):
    """[TODO:description]

    Attributes:
        username: [TODO:attribute]
        password: [TODO:attribute]
        token_policies: [TODO:attribute]
    """

    username: str
    password: str
    token_policies: List[str]


class UserpassAuthMethodConfig(BaseModel):
    """[TODO:description]

    Attributes:
        users: [TODO:attribute]
    """

    users: List[UserpassAuthMethodConfigUsers]


# TODO: Implement this
class TokenAuthMethodConfig(BaseModel):
    pass


class VaultAuthMethod(BaseModel):
    type: str
    path: str
    method_config: Optional[
        Union[
            UserpassAuthMethodConfig, TokenAuthMethodConfig, KubernetesAuthMethodConfig
        ]
    ] = None


class VaultKVSecretEngine(BaseModel):
    """[TODO:description]

    Attributes:
        path: [TODO:attribute]
        type: [TODO:attribute]
    """

    path: str
    type: str


class StartupSecret(BaseModel):
    path: str
    mount_point: str
    type: str
    data: Dict


class Configuration(BaseModel):
    setting: Setting
    policies: List[VaultPolicy]
    auth: List[VaultAuthMethod]
    secret_engines: List[VaultKVSecretEngine]
    startup_secrets: List[StartupSecret]


def load_config_file(config_path: str) -> Configuration:
    try:
        with open(os.path.expanduser(config_path), "r") as f:
            config = yaml.safe_load(f) or {}
            return Configuration(**config)
    except FileNotFoundError:
        raise click.ClickException(f"No config file at {config_path} (Skipping)")
    except IOError:
        raise click.ClickException(
            f"Config file exists at {config_path}, but cannot be read. "
            "Have you checked permission? (Skipping)"
        )


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


################
#### Client ####
################


@contextlib.contextmanager
def handle_client_errors():
    try:
        yield
    except client_exception.UnexpectedError as exc:
        raise VaultAPIException(errors=exc.errors) from exc
    # TODO: Add handle not authentication exception
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
    def health_status(self):
        """Read the health status of Vault."""
        return self.client.sys.read_health_status(method="GET")

    @handle_client_errors()
    def initialize(self, shares: int, threshold: int) -> JSONDict:
        """Initialize a new Vault."""
        return self.client.sys.initialize(shares, threshold)

    @handle_client_errors()
    def auth_methods_list(self) -> JSONDict:
        """List all enabled auth methods."""
        return self.client.sys.list_auth_methods().get("data") or {}

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
        return (
            self.client.auth.kubernetes.list_roles(mount_point=mount_point).get("keys")
            or []
        )

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
        return (
            self.client.auth.userpass.list_user(mount_point=mount_point)["data"]["keys"]
            or []
        )

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

    # @handle_client_errors()
    # def secrets_engines_read_config(self, path: str) -> JSONDict:
    #     return self.client.sys.read_mount_configuration(path=path)
    #
    # @handle_client_errors()
    # def secrets_engines_tune_configs(self) -> JSONDict:
    #     return {}

    def _browse_recursive_secrets(self, path: str, mount_point: str) -> Iterable[str]:
        """
        Given a secret or folder path, return the path of all secrets
        under it (or the path itself)
        """
        # 4 things can happen:
        # - path is "", it's the root (and a folder)
        # - path ends with /, we know it's a folder
        # - path doesn't end with a / and yet it's a folder
        # - path is a secret
        folder = path.endswith("/") or path == ""

        sub_secrets = self.kvv2_secrets_list(path=path, mount_point=mount_point)

        if not folder and not sub_secrets:
            # It's most probably a secret
            yield path

        for key in sub_secrets:
            folder = key.endswith("/")
            key = key.rstrip("/")
            key_url = f"{path}/{key}" if path else key
            if not folder:
                yield key_url
                continue

            for sub_path in self._browse_recursive_secrets(key_url, mount_point):
                yield sub_path

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
        if self.client.is_initialized():
            return [], ""  # Return early if already initialized

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

    def unseal_instance(
        self, keys: list = [], instance_name: str = "vault", namespace: str = "vault"
    ) -> None:
        """[TODO:description]

        Args:
            keys: [TODO:description]
            instance_name: [TODO:description]
            namespace: [TODO:description]
        """
        cluster_domain = "cluster.local"  # TODO: Move it to env
        service = "vault-internal"
        vault_port = 8200
        for key in keys:
            operator = f"vault operator unseal --address http://{instance_name}.{service}.{namespace}.svc.{cluster_domain}:{vault_port} {key}"
            command = ["/bin/sh", "-c", f"{operator}"]
            click.echo(f"Unseal instace: {instance_name} successfully!")
            execute_command_in_pod(
                pod_name=instance_name,
                namespace=namespace,
                command=command,
            )

    def unseal_all(
        self, keys: list = [], instance_list: list = [], namespace: str = "vault"
    ) -> None:
        """[TODO:description]

        Args:
            keys: [TODO:description]
            instance_list: [TODO:description]
            namespace: [TODO:description]
        """
        for instance in instance_list:
            self.unseal_instance(keys=keys, instance_name=instance, namespace=namespace)

    def sync_policy(self, policies: List, remove_orphans: bool = False):
        """Sync policies from configurations to Vault.

        Args:
            policies: A list of policies from the configurations.
            remove_orphan: A boolean indicating whether to remove orphan policies from Vault.

        Returns:
            A list of strings representing any errors encountered during the sync process.  Returns an empty list if successful.
        """
        errors = []
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
                    # WARNING: Compare logic maybe fail because policy string in Vault has been pretty formatting.
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

    def sync_authmethods(self, authmethods: List, remove_orphans: bool = False) -> List:
        errors = []
        try:
            # Get Authentication methods from Vault
            vault_authmethods = [
                {"path": path, "type": details["type"]}
                for path, details in self.client.auth_methods_list().items()  # BUG: Fail when empty auth method list
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

        except Exception as exc:
            errors.append(f"An unexpected error occurred: {exc}")

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

        except Exception as exc:
            errors.append(f"An unexpected error occurred: {exc}")

    # TODO: Implement this
    def _sync_token_authmethod_config(self, config: TokenAuthMethodConfig):
        pass

    def sync_kvv2_secretengines(
        self, secrets_engines: List[VaultKVSecretEngine], remove_orphans: bool = False
    ) -> List:
        errors = []
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

    def sync_secrets(self, startup_secrets: List, remove_orphans: bool = False) -> List:
        errors = []
        try:
            for secret in startup_secrets:
                self.client.kvv2_secrets_create_or_update(
                    path=secret.path, mount_point=secret.mount_point, secret=secret.data
                )

        except Exception as exc:
            errors.append(f"An unexpected error occurred: {exc}")

        return errors


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
    "-V",
    "--version",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
)
def cli(ctx: click.Context, config_path: str, **kwargs) -> None:
    """
    Interact with a Vault. See subcommands for details.

    All arguments can be passed by environment variables: VAULT_CLI_UPPERCASE_NAME
    (including VAULT_CLI_PASSWORD and VAULT_CLI_TOKEN).

    """
    ctx.ensure_object(dict)
    ctx.obj = CLIContext(VaultClient(**kwargs), load_config_file(config_path))


@cli.command()
def bootstrap() -> None:
    """
    Bootstrap the target Vault cluster

    This command will verify the configurations, run "vault init" against the target Vault instance,
    before storing the token, keys in the given output path.

    After initializing, it will unseal the Vault cluster and apply the predefined configurations.
    """
    # Create raw Vault client
    # client = VaultClient(url=url)

    # Check Vault connection
    # client.init_status()
    click.echo("Ping ok!")

    # Validate configurations
    # NOTE: Check vault init status before init ?

    # Initialize Vault

    # NOTE: Check when vault cluster is initialize OK
    # time.sleep(10)
    #
    # client.token = result["root_token"]
    # client.auth()

    # Verify Vault status
    # Check vault seal status before unseal
    # Apply predefined configurations
    # Create startup secrets


@cli.command()
@click.pass_obj
def unseal(client_obj: VaultClient) -> None:
    """
    Unseals Vault with unseal keys provide from command line.

    It will continuously attempt to unseal the target Vault instance, by retrieving unseal keys
    from command line.
    """
    click.echo("Done")


@cli.command()
@click.pass_obj
@click.option(
    "--remove_orphans",
    "-ro",
    help="Remove orphans data",
    is_flag=True,
    default=False,
    show_default=True,
)
def sync_configs(ctx: CLIContext, remove_orphans: bool):
    """Synchronizes configurations from a file to Vault.

    Reads configuration data from the file specified by `CONFIG_FILE_PATH` (an environment variable or configuration setting),
    and pushes this data to the Vault server.
    """
    # Client Authentication
    ctx.client.auth(
        token=ctx.cfg.setting.token,
        username=ctx.cfg.setting.username,
        password=ctx.cfg.setting.password,
    )
    errors = []
    commands = Commands(ctx.client)
    errors = errors + commands.sync_policy(ctx.cfg.policies, remove_orphans)
    errors = errors + commands.sync_authmethods(ctx.cfg.auth, remove_orphans)
    errors = errors + commands.sync_kvv2_secretengines(
        ctx.cfg.secret_engines, remove_orphans
    )

    if errors:
        for err in errors:
            click.echo(err)
    else:
        click.echo("All configurations is synced. Feel happy. ^^")


@cli.command()
@click.pass_obj
@click.option(
    "--remove_orphans",
    "-ro",
    help="Remove orphans data",
    is_flag=True,
    default=False,
    show_default=True,
)
def sync_secrets(ctx: CLIContext, remove_orphans: bool):
    # Client Authentication
    ctx.client.auth(
        token=ctx.cfg.setting.token,
        username=ctx.cfg.setting.username,
        password=ctx.cfg.setting.password,
    )
    commands = Commands(ctx.client)
    errors = commands.sync_secrets(ctx.cfg.startup_secrets, remove_orphans)

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
