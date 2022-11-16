import contextlib
import logging
import socket
import tempfile
from pathlib import Path
from typing import List

import paramiko
from plumbum import local
from pyimg4 import IMG4, IM4P, Compression

from pylera1n import interactive
from pylera1n.common import PALERA1N_PATH, path_to_str, OS_VARIANT

logger = logging.getLogger(__name__)

APTICKET_DEVICE_PATH = Path('/dev/rdisk1')


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

    def exec(self, command: str) -> tuple:
        stdin, stdout, stderr = self._ssh.exec_command(command)
        stdout = stdout.read()
        stderr = stderr.read()
        return stdout, stderr

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

        while len(self.listdir('/mnt2')) == 0:
            pass

        stdout, stderr = self.exec('/usr/bin/find /mnt2/containers/Bundle/Application/ -name Tips.app')
        tips_dir = stdout.strip().decode()
        if not tips_dir:
            logger.warning(
                'Tips is not installed. Once your device reboots, install Tips from the App Store and retry')
            self.reboot()
            return

        # removing old files that may break signature check if any
        self.remove('/usr/local/bin/loader.app/Info.plist', force=True)
        self.remove('/usr/local/bin/loader.app/Base.lproj', force=True)
        self.remove('/usr/local/bin/loader.app/PkgInfo', force=True)

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

    def place_kernelcachd_using_pongo_kpf(self, preboot_device: Path, local_kernelcache: Path) -> None:
        logger.info('patching kernel using pongo kpf')

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

            with self.get_active_preboot(preboot_device) as preboot:
                remote_kcache_raw = f'{preboot}/System/Library/Caches/com.apple.kernelcaches/kcache.raw'
                remote_kcache_patched = f'{preboot}/System/Library/Caches/com.apple.kernelcaches/kcache.patched'
                remote_kernelcachd = f'{preboot}/System/Library/Caches/com.apple.kernelcaches/kernelcachd'
                remote_im4p = f'{preboot}/System/Library/Caches/com.apple.kernelcaches/kcache.im4p'

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
                          f'-M {preboot}/System/Library/Caches/apticket.der')
                self.chmod(remote_kernelcachd, 0o644)

                # remove temp files if any
                self.remove(remote_kcache_raw, force=True)
                self.remove(remote_kcache_patched, force=True)
                self.remove(remote_im4p, force=True)

    @contextlib.contextmanager
    def get_active_preboot(self, preboot_device: Path) -> Path:
        mountpoint = Path(f'/mnt{str(preboot_device)[-1]}')
        self.umount(mountpoint)
        self.mount_apfs(preboot_device, mountpoint)
        preboot = Path(mountpoint)
        active_uuid = self.cat(preboot / 'active').strip().decode()
        try:
            yield preboot / active_uuid
        finally:
            self.umount(mountpoint)

    @property
    def apticket(self) -> bytes:
        return IMG4(self.cat(APTICKET_DEVICE_PATH)).im4m.output()

    def reboot(self) -> None:
        logger.info('rebooting')
        self.exec_async('/sbin/reboot')

    def set_nvram_value(self, key: str, value: str):
        self.exec(f'/usr/sbin/nvram {key}="{value}"')

    def get_nvram_value(self, key: str) -> str:
        stdout, stderr = self.exec(f'/usr/sbin/nvram {key}')
        return stdout.strip()

    @path_to_str('device')
    @path_to_str('mountpoint')
    def mount_apfs(self, device: str, mountpoint: str) -> None:
        self.exec(f'/sbin/mount_apfs {device} {mountpoint}')

    @path_to_str('path')
    def umount(self, path: str) -> None:
        self.exec(f'/sbin/umount {path}')

    @path_to_str('path')
    def cat(self, path: str) -> bytes:
        stdout, stderr = self.exec(f'cat {path}')
        return stdout

    def close(self) -> None:
        self._sftp.close()
        self._ssh.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
