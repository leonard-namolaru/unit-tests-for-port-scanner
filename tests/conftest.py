from paramiko.client import SSHClient
import paramiko
import pytest
import re


def path_checker(value):
    error_msg = "Un chemin de fichier correct ne doit inclure que les caractères a-z A-Z 0-9_ . / "
    if re.match(r'[^a-zA-Z0-9_\\./]+', value) is not None:
        raise pytest.UsageError(error_msg)
    return value


def host_checker(value):
    error_msg = "Un nom de serveur valide ne doit inclure que les caractères suivants : a-z A-Z 0-9 _ . /"
    if re.match(r'[^a-zA-Z0-9_\\./]+', value) is not None:
        raise pytest.UsageError(error_msg)
    return value


def identifier_checker(value):
    error_msg = "Un nom d'utilisateur valide ne doit inclure que les caractères suivants : a-z A-Z 0-9 _"
    if re.match(r'[^a-zA-Z0-9_]+', value) is not None:
        raise pytest.UsageError(error_msg)
    return value


def pytest_addoption(parser):
    parser.addoption("--host", action="store", help="host ip", type=host_checker, default="127.0.0.1")
    parser.addoption("--username", action="store", help="ssh user", type=identifier_checker, default="root")
    parser.addoption("--pkey", action="store", help="ssh user", type=path_checker, default="./id_rsa")


@pytest.fixture(scope="session")
def host(request):
    return request.config.getoption("--host")


@pytest.fixture(scope="session")
def username(request):
    return request.config.getoption("--username")


@pytest.fixture(scope="session")
def pkey(request):
    return request.config.getoption("--pkey")


@pytest.fixture(scope="session")
def key_based_ssh_connection(host, username, pkey):
    private_key = paramiko.RSAKey.from_private_key_file(pkey)
    ssh_client = paramiko.SSHClient()
    policy = paramiko.AutoAddPolicy()

    ssh_client.set_missing_host_key_policy(policy)
    ssh_client.connect(host, username=username, pkey=private_key)
    return ssh_client


@pytest.fixture(scope="function")
def ssh_connection_after_iptables_reset(key_based_ssh_connection):
    exec_ssh_command_with_error_handling(key_based_ssh_connection, 'sudo iptables -F')
    exec_ssh_command_with_error_handling(key_based_ssh_connection, 'sudo iptables -X')
    return key_based_ssh_connection


def exec_ssh_command_with_error_handling(ssh_connection: SSHClient, command: str) -> None:
    _stdin, _stdout, _stderr = ssh_connection.exec_command(command)

    error_message = _stderr.read().decode()
    if len(error_message) > 0:
        raise RuntimeError(error_message)
    return
