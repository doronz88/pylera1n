import socket

import paramiko

from pylera1n import interactive


class SSHClient:
    def __init__(self, sock: socket.socket):
        self._sock = sock

        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._ssh.connect('pylera1n-device', look_for_keys=False, username='root', password='alpine', sock=sock)
        self._sftp = self._ssh.open_sftp()

    def interact(self) -> None:
        interactive.interactive_shell(self._ssh.invoke_shell())

    def exec(self, command: str) -> tuple:
        return self._ssh.exec_command(command)

    def put_file(self, src: str, dest: str) -> None:
        self._sftp.put(src, dest)
        self._sftp.chmod(dest, 0o777)

    def close(self) -> None:
        self._sftp.close()
        self._ssh.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
