import logging
import socket
from pathlib import Path

import paramiko
from pyimg4 import IMG4

from pylera1n import interactive

logger = logging.getLogger(__name__)


class SSHClient:
    def __init__(self, sock: socket.socket):
        self._sock = sock

        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._ssh.connect('pylera1n-device', look_for_keys=False, username='root', password='alpine', sock=sock)
        self._sftp = self._ssh.open_sftp()

    @property
    def auto_boot(self):
        return bool(self.get_nvram_value('auto-boot'))

    @auto_boot.setter
    def auto_boot(self, value: bool):
        self.set_nvram_value('auto-boot', str(value).lower())

    def interact(self) -> None:
        interactive.interactive_shell(self._ssh.invoke_shell())

    def exec(self, command: str) -> tuple:
        return self._ssh.exec_command(command)

    def put_file(self, src: str, dest: str) -> None:
        self._sftp.put(src, dest)
        self._sftp.chmod(dest, 0o777)

    def chmod(self, path: str, mode: int) -> None:
        self._sftp.chmod(path, mode)

    def mount_filesystems(self) -> None:
        self.exec('/usr/bin/mount_filesystems')

    def enable_development_options(self) -> None:
        logger.info('enabling development options')
        self.set_nvram_value('boot-args',
                             '-v keepsyms=1 debug=0x2014e launchd_unsecure_cache=1 launchd_missing_exec_no_panic=1 '
                             'amfi=0xff amfi_allow_any_signature=1 amfi_get_out_of_my_way=1 amfi_allow_research=1 '
                             'amfi_unrestrict_task_for_pid=1 '
                             'amfi_unrestricted_local_signing=1 cs_enforcement_disable=1 '
                             'pmap_cs_allow_modified_code_pages=1 pmap_cs_enforce_coretrust=0 '
                             'pmap_cs_unrestrict_pmap_cs_disable=1 -unsafe_kernel_text dtrace_dof_mode=1 '
                             'panic-wait-forever=1 -panic_notify cs_debug=1 PE_i_can_has_debugger=1')
        self.set_nvram_value('allow-root-hash-mismatch', '1')
        self.set_nvram_value('oot-live-fs', '1')

    def install_pogo(self) -> None:
        logger.info('installing Pogo')

        logger.info('mounting filesystems')
        self.mount_filesystems()

        while True:
            stdin, stdout, stderr = self.exec('/bin/ls /mnt2')
            if stdout.read().strip():
                break

        stdin, stdout, stderr = self.exec('/usr/bin/find /mnt2/containers/Bundle/Application/ -name Tips.app')
        tips_dir = stdout.read().strip().decode()
        if not tips_dir:
            logger.warning(
                'Tips is not installed. Once your device reboots, install Tips from the App Store and retry')
            self.reboot()
            return

        logger.info(f'copying /usr/local/bin/loader.app/* -> {tips_dir}/*')
        self.exec(f'/bin/cp -rf /usr/local/bin/loader.app/* {tips_dir}')

        logger.info('fixing Tips.app permissions')
        self.exec(f'/usr/sbin/chown 33 {tips_dir}/Tips')
        self.exec(f'/bin/chmod 755 {tips_dir}/Tips {tips_dir}/PogoHelper')
        self.exec(f'/usr/sbin/chown 0 {tips_dir}/PogoHelper')

    def dump_blobs(self, path: Path) -> None:
        logger.info(f'saving blobs into: {path}')
        stdin, stdout, stderr = self.exec('cat /dev/rdisk1')
        path.write_bytes(IMG4(stdout.read()).im4m.output())

    def reboot(self) -> None:
        self.exec('/sbin/reboot')

    def set_nvram_value(self, key: str, value: str):
        self.exec(f'/usr/sbin/nvram {key}="{value}"')

    def get_nvram_value(self, key: str) -> str:
        stdin, stdout, stderr = self.exec(f'/usr/sbin/nvram {key}')
        return stdout.read().strip()

    def close(self) -> None:
        self._sftp.close()
        self._ssh.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
