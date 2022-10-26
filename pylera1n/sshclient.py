import socket

import paramiko

from pylera1n import interactive


class SSHClient:
    def __init__(self, sock: socket.socket):
        self._sock = sock

        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._ssh.connect('pylera1n-device', look_for_keys=False, username='root', password='alpine', sock=sock)

    def interact(self) -> None:
        interactive.interactive_shell(self._ssh.invoke_shell())

    def exec(self, command: str) -> tuple:
        return self._ssh.exec_command(command)

    def close(self) -> None:
        self._ssh.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
