import dataclasses
import logging
import os
import socket
import tempfile
from pathlib import Path
from stat import S_ISDIR
from typing import List, Dict

import paramiko
from plumbum import local
from pyimg4 import IM4P, Compression

from pylera1n import interactive
from pylera1n.common import PALERA1N_PATH, path_to_str, OS_VARIANT
from pylera1n.exceptions import DirectoryNotEmptyError, MissingActivePrebootError, MountError, \
    ProcessExecutionFailedError

logger = logging.getLogger(__name__)

APTICKET_DEVICE_PATH = Path('/dev/rdisk1')


@dataclasses.dataclass
class ProcessExecutionResult:
    exitcode: int
    stdout: bytes
    stderr: bytes


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

    def exec_async(self, command: str) -> tuple:
        stdin, stdout, stderr = self._ssh.exec_command(command)
        return stdin, stdout, stderr

    def exec(self, command: str) -> ProcessExecutionResult:
        stdin, stdout, stderr = self._ssh.exec_command(command)
        stdout_buf = stdout.read()
        stderr_buf = stderr.read()
        exitcode = stdout.channel.recv_exit_status()

        if exitcode != 0:
            raise ProcessExecutionFailedError(f'execution on: {command} failed with: {exitcode}')

        return ProcessExecutionResult(exitcode=exitcode, stdout=stdout_buf, stderr=stderr_buf)

    @path_to_str('src')
    @path_to_str('dst')
    def put_file(self, src: str, dst: str) -> None:
        self._sftp.put(src, dst)
        self._sftp.chmod(dst, 0o777)

    @path_to_str('src')
    @path_to_str('dst')
    def get_file(self, src: str, dst: str) -> None:
        self._sftp.get(src, dst)

    @path_to_str('path')
    def remove(self, path: str, force=False) -> None:
        try:
            self._sftp.remove(path)
        except FileNotFoundError:
            if not force:
                raise

    @path_to_str('path')
    def isdir(self, path: str) -> bool:
        return S_ISDIR(self._sftp.stat(path).st_mode)

    @path_to_str('path')
    def rmdir(self, path: str, recursive=False, force=False) -> None:
        try:
            files = self.listdir(path)
        except FileNotFoundError:
            if not force:
                raise
        if files:
            if recursive:
                for f in files:
                    file_path = os.path.join(path, f)
                    if self.isdir(file_path):
                        self.rmdir(file_path, recursive, force)
                    else:
                        self.remove(file_path, force)
            else:
                raise DirectoryNotEmptyError(
                    f'Tried to delete non-empty directory {path} without passing recursive flag')
        self._sftp.rmdir(path)

    @path_to_str('path')
    def listdir(self, path: str) -> List[str]:
        path = str(path)
        return self._sftp.listdir(path)

    @path_to_str('path')
    def chmod(self, path: str, mode: int) -> None:
        self._sftp.chmod(path, mode)

    @path_to_str('path')
    def chown(self, path: str, owner: int) -> None:
        self._sftp.chown(path, owner, owner)

    def mount_filesystems(self) -> None:
        logger.info('mounting filesystems')
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

        while len(self.listdir('/mnt2')) == 0:
            pass

        tips_dir = self.exec(
            '/usr/bin/find /mnt2/containers/Bundle/Application/ -name Tips.app').stdout.strip().decode()
        if not tips_dir:
            logger.warning(
                'Tips is not installed. Once your device reboots, install Tips from the App Store and retry')
            self.reboot()
            return

        # removing old files that may break signature check if any
        self.remove(f'{tips_dir}/Info.plist', force=True)
        self.rmdir(f'{tips_dir}/Base.lproj', recursive=True, force=True)
        self.remove(f'{tips_dir}/PkgInfo', force=True)

        logger.info(f'copying /usr/local/bin/loader.app/* -> {tips_dir}/*')
        self.exec(f'/bin/cp -rf /usr/local/bin/loader.app/* {tips_dir}')

        logger.info('fixing Tips.app permissions')
        self.exec(f'/usr/sbin/chown 33 {tips_dir}/Tips')
        self.exec(f'/bin/chmod 755 {tips_dir}/Tips {tips_dir}/PogoHelper')
        self.exec(f'/usr/sbin/chown 0 {tips_dir}/PogoHelper')

    def create_fakefs(self) -> None:
        logger.info('creating fakefs')
        try:
            self._sftp.stat('/dev/disk0s1s8')
        except FileNotFoundError:
            self.exec('/sbin/newfs_apfs -A -D -o role=r -v System /dev/disk0s1')

        self.mount_apfs('/dev/disk0s1s8', '/mnt8')
        self.exec('cp -a /mnt1/. /mnt8/')
        self.umount('/mnt8')

    def place_kernelcachd_using_pongo_kpf(self, local_kernelcache: Path) -> None:
        logger.info('patching kernel using pongo kpf')

        self.mount_apfs('/dev/disk0s1s1', '/mnt1')
        kpf_executable = '/mnt1/private/var/root/Kernel15Patcher.ios'

        logger.info('placing pongo kpf')
        self.put_file(PALERA1N_PATH / 'binaries' / 'Kernel15Patcher.ios', kpf_executable)
        self.chown(kpf_executable, 0)
        self.chmod(kpf_executable, 0o777)

        im4p = IM4P(local_kernelcache.read_bytes())
        im4p.payload.decompress()
        kpp = im4p.payload.extra

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)

            local_kcache_raw = temp_dir / 'kcache.raw'
            local_kcache_raw.write_bytes(im4p.payload.output().data)

            remote_kcache_raw = f'{self.active_preboot}/System/Library/Caches/com.apple.kernelcaches/kcache.raw'
            remote_kcache_patched = f'{self.active_preboot}/System/Library/Caches/com.apple.kernelcaches/kcache.patched'
            remote_kernelcachd = f'{self.active_preboot}/System/Library/Caches/com.apple.kernelcaches/kernelcachd'
            remote_im4p = f'{self.active_preboot}/System/Library/Caches/com.apple.kernelcaches/kcache.im4p'

            # remove temp files if any
            self.remove(remote_kcache_raw, force=True)
            self.remove(remote_kcache_patched, force=True)
            self.remove(remote_kernelcachd, force=True)
            self.remove(remote_im4p, force=True)

            # placing raw kernel
            self.put_file(local_kcache_raw, remote_kcache_raw)

            # patch using pongo kpf
            self.exec(f'{kpf_executable} {remote_kcache_raw} {remote_kcache_patched}')

            # applying our own patches
            temp_dir = Path(temp_dir)
            local_kcache_patched1 = temp_dir / 'kcache.patched'
            local_kcache_patched2 = temp_dir / 'kcache.patched2'
            self.get_file(remote_kcache_patched, local_kcache_patched1)

            local[str(PALERA1N_PATH / 'binaries' / OS_VARIANT / 'Kernel64Patcher')](local_kcache_patched1,
                                                                                    local_kcache_patched2, '-o',
                                                                                    '-e', '-u')
            im4p = IM4P(fourcc='krnl', payload=local_kcache_patched2.read_bytes())
            im4p.payload.compress(Compression.LZSS)
            im4p.payload.extra = kpp

            local_im4p = temp_dir / 'kcache.im4p'
            local_im4p.write_bytes(im4p.output())

            self.put_file(local_im4p, remote_im4p)
            self.exec(f'img4 '
                      f'-i {remote_im4p} '
                      f'-o {remote_kernelcachd} '
                      f'-M {self.active_preboot}/System/Library/Caches/apticket.der')
            self.chmod(remote_kernelcachd, 0o644)

            # remove temp files if any
            self.remove(remote_kcache_raw, force=True)
            self.remove(remote_kcache_patched, force=True)
            self.remove(remote_im4p, force=True)

    @property
    def active_preboot(self) -> Path:
        active_uuid = self.cat('/mnt6/active').strip().decode()
        if not active_uuid:
            raise MissingActivePrebootError()
        return Path(f'/mnt6/{active_uuid}')

    @property
    def apticket(self) -> bytes:
        return self.cat(self.active_preboot / 'System/Library/Caches/apticket.der')

    def reboot(self) -> None:
        logger.info('rebooting')
        self.exec_async('/sbin/reboot')

    def set_nvram_value(self, key: str, value: str):
        self.exec(f'/usr/sbin/nvram {key}="{value}"')

    def get_nvram_value(self, key: str) -> str:
        return self.exec(f'/usr/sbin/nvram {key}').stdout.strip()

    def get_current_mounts(self) -> Dict[str, str]:
        current_mounts = {}
        mounts = self.exec('/sbin/mount').stdout.decode().splitlines()
        for mount in mounts:
            mount = mount.split(' ')
            if mount[1] != 'on':
                raise MountError(f'Unexpected format of mount point: {mount}')
            current_mounts[mount[0]] = mount[2]
        return current_mounts

    @path_to_str('device')
    def mount_apfs(self, device: str, mountpoint: str = None) -> str:
        current_mounts = self.get_current_mounts()
        if device in current_mounts:
            device_mountpoint = current_mounts[device]
            if mountpoint and device_mountpoint != mountpoint:
                raise MountError(f'{device} can\'t be mounted at {mountpoint}'
                                 f'since it is already mounted at {current_mounts[device]}')
            else:
                return device_mountpoint
        if not mountpoint:
            taken_mountpoints = current_mounts.values()
            available_mountpoints = ['/' + path for path in self.listdir('/') if path.startswith('mnt')]
            available_mountpoints = [path for path in available_mountpoints if path not in taken_mountpoints]
            mountpoint = available_mountpoints[0]
        return mountpoint

    @path_to_str('path')
    def umount(self, path: str) -> None:
        self.exec(f'/sbin/umount {path}')

    @path_to_str('path')
    def cat(self, path: str) -> bytes:
        return self.exec(f'cat {path}').stdout

    def close(self) -> None:
        self._sftp.close()
        self._ssh.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
