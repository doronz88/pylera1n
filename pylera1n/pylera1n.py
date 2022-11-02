import logging
import os
import shutil
import tempfile
import time
from io import BytesIO
from pathlib import Path
from typing import Optional
from zipfile import ZipFile

import requests
from paramiko.config import SSH_PORT
from plumbum import local
from pyimg4 import IM4P, Compression
from pyipsw.pyipsw import get_devices
from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import NoDeviceConnectedError, IRecvNoDeviceConnectedError, ConnectionFailedError
from pymobiledevice3.irecv import IRecv, Mode
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.restore.img4 import img4_get_component_tag
from pymobiledevice3.restore.ipsw.ipsw import IPSW
from pymobiledevice3.services.diagnostics import DiagnosticsService
from remotezip import RemoteZip
from tqdm import trange
from usb import USBError

from pylera1n.exceptions import MissingProductVersionError
from pylera1n.sshclient import SSHClient

logger = logging.getLogger(__name__)

OS_VARIANT = os.uname().sysname
DEFAULT_STORAGE = Path('~/.pylera1n').expanduser()


def wait(seconds: int) -> None:
    for _ in trange(seconds):
        time.sleep(1)


def download_gaster(output: Path, os_version: str = os.uname().sysname):
    logger.info('downloading gaster')
    gaster_zip = requests.get(
        f'https://nightly.link/verygenericname/gaster/workflows/makefile/main/gaster-{os_version}.zip').content
    gaster_zip = ZipFile(BytesIO(gaster_zip))
    with gaster_zip.open('gaster') as f:
        output.write_bytes(f.read())
        output.chmod(0o755)


def download_pogo(output: Path) -> None:
    logger.info('downloading pogo')
    pogo = requests.get('https://nightly.link/elihwyma/Pogo/workflows/build/root/Pogo.zip').content
    pogo = ZipFile(BytesIO(pogo))
    with pogo.open('Pogo.ipa') as f:
        output.write_bytes(f.read())


RESTORE_COMPONENTS = ('iBSS', 'iBEC', 'RestoreDeviceTree', 'RestoreRamDisk', 'RestoreTrustCache',
                      'RestoreKernelCache', 'RestoreLogo')

BOOT_COMPONENTS = ('iBSS', 'iBEC', 'DeviceTree', 'StaticTrustCache', 'KernelCache', 'RestoreLogo')


class Pylera1n:
    def __init__(self, palera1n: Path, product_version: str = None, ramdisk_ipsw: str = None, ipsw: str = None,
                 devel=True, storage: Path = DEFAULT_STORAGE):
        storage.mkdir(parents=True, exist_ok=True)
        self._storage = storage

        gaster_path = storage / 'gaster'
        if not gaster_path.exists():
            download_gaster(gaster_path)

        pogo_path = storage / 'Pogo.ipa'
        if not pogo_path.exists():
            download_pogo(pogo_path)

        self._board_id = None
        self._chip_id = None
        self._hardware_model: Optional[str] = None
        self._product_type = None
        self._product_version = product_version
        self._palera1n = palera1n
        self._binaries = palera1n / 'binaries' / OS_VARIANT
        self._ramdisk = palera1n / 'ramdisk'
        self._gaster = local[str(gaster_path)]
        self._img4tool = local[str(self._binaries / 'img4tool')]
        self._img4 = local[str(self._binaries / 'img4')]
        self._iboot64patcher = local[str(self._binaries / 'iBoot64Patcher')]
        self._kernel64patcher = local[str(self._binaries / 'Kernel64Patcher')]
        self._gtar = local[str(self._ramdisk / os.uname().sysname / 'gtar')]
        self._hdiutil = None if os.uname().sysname != 'Darwin' else local['hdiutil']
        self._ramdisk_ipsw_path = ramdisk_ipsw
        self._ramdisk_ipsw: Optional[IPSW] = None
        self._ipsw_path = ipsw
        self._ipsw: Optional[IPSW] = None
        self._devel = devel
        self._tips = ZipFile(pogo_path)
        self._init_device_info()

        if self._product_version is None:
            raise MissingProductVersionError()

        shsh_blob_dir = self._storage / 'shsh'
        shsh_blob_dir.mkdir(exist_ok=True, parents=True)
        self._shsh_blob = shsh_blob_dir / f'{self._hardware_model}-{self._product_version}.shsh'

        self._ramdisk_dir = self._storage / 'ramdisk' / self._hardware_model
        self._ramdisk_dir.mkdir(exist_ok=True, parents=True)

        self._boot_dir = self._storage / 'boot' / self._hardware_model
        self._boot_dir.mkdir(exist_ok=True, parents=True)

        self._bpatch_file = self._storage / 'patches' / f'{self._hardware_model.replace("ap", "")}.bpatch'

    @property
    def in_dfu(self) -> bool:
        try:
            with LockdownClient():
                return False
        except ConnectionFailedError:
            # the device is in the midst of a reboot
            return False
        except NoDeviceConnectedError:
            with IRecv(timeout=1) as irecv:
                return irecv.mode == Mode.DFU_MODE

    def jailbreak(self, recreate_ramdisk=False, recreate_boot=False) -> None:
        logger.info('jailbreaking')

        if not self._shsh_blob.exists() or recreate_ramdisk:
            logger.info('creating ramdisk')
            self.ramdisk_stage(recreate_ramdisk=recreate_ramdisk)

        self.enter_dfu()
        self.pwn()

        if not self.has_prepared_boot or recreate_boot:
            self.create_patched_boot()

        self._boot_boot()

    def boot_ramdisk(self, recreate_ramdisk=False) -> None:
        """ boot into ramdisk """
        logger.info('waiting for device to enter DFU')
        self.enter_dfu()
        logger.info('pwn-ing device')
        self.pwn()

        if not self.has_prepared_ramdisk or recreate_ramdisk:
            self.create_ramdisk()
        self._boot_ramdisk()

    @property
    def has_prepared_ramdisk(self) -> bool:
        for component in RESTORE_COMPONENTS:
            if not ((self._ramdisk_dir / component).with_suffix('.img4').exists()):
                return False
        return True

    @property
    def has_prepared_boot(self) -> bool:
        for component in BOOT_COMPONENTS:
            if not ((self._boot_dir / component).with_suffix('.img4').exists()):
                return False
        return True

    def ramdisk_stage(self, recreate_ramdisk=False) -> None:
        """ create blobs, install pogo and patch nvram if on non-rootless """
        self.boot_ramdisk(recreate_ramdisk)

        device = None

        logger.info('waiting for device to be recognized via usb')

        while device is None:
            # wait for device to boot
            device = usbmux.select_device()

        logger.info('waiting for ssh server to start')

        sock = None
        while sock is None:
            # wait for ssh server to start
            sock = device.connect(SSH_PORT)

        with SSHClient(sock) as ssh:
            self._install_pogo(ssh)
            if self._devel:
                self._disable_nvram_stuff(ssh)
            self._dump_blobs(ssh)

            # make sure device reboots into recovery
            ssh.exec('/usr/sbin/nvram auto-boot=false')
            ssh.exec('/sbin/reboot')

    @staticmethod
    def exec_ssh_command(command: str) -> None:
        sock = usbmux.select_device().connect(SSH_PORT)
        with SSHClient(sock) as ssh:
            ssh.exec(command)

    def create_ramdisk(self) -> None:
        if self._ramdisk_ipsw is None:
            self._init_ramdisk_ipsw()

        logger.info('creating ramdisk')

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)

            im4m = temp_dir / 'IM4M'
            self._img4tool('-e', '-s', self._ramdisk / 'shsh' / f'0x{self._chip_id:x}.shsh', '-m', im4m)
            build_identity = self._ramdisk_ipsw.build_manifest.get_build_identity(self._hardware_model)

            # use costume RestoreLogo
            self.create_img4(self._palera1n / 'other' / 'bootlogo.im4p', self._ramdisk_dir / 'RestoreLogo.img4', im4m,
                             img4_get_component_tag('RestoreLogo').decode(), wrap=True)

            # extract
            for component in ('iBSS', 'iBEC', 'RestoreDeviceTree', 'RestoreRamDisk', 'RestoreTrustCache',
                              'RestoreKernelCache'):
                logger.info(f'patching {component}')

                local_component = temp_dir / component
                local_component.write_bytes(self._ramdisk_ipsw.read(build_identity.get_component_path(component)))

                im4p = local_component
                img4 = (self._ramdisk_dir / component).with_suffix('.img4')
                fourcc = img4_get_component_tag(component).decode()
                patch = None
                wrap = component in ('iBSS', 'iBEC', 'RestoreRamDisk')

                # patch bootloader
                if component in ('iBSS', 'iBEC'):
                    iboot = local_component
                    decrypted_iboot = iboot.with_suffix('.dec')
                    self.decrypt(iboot, decrypted_iboot)
                    patched_iboot = iboot.with_suffix('.patched')

                    if iboot.parts[-1] == 'iBEC':
                        boot_args = 'rd=md0 debug=0x2014e -v wdt=-1 '
                        if self._chip_id in (0x8960, 0x7000, 0x7001):
                            # TODO: macos variant?
                            boot_args += '-restore'
                        self.patch_iboot_component(decrypted_iboot, patched_iboot, boot_args)
                    else:
                        self.patch_iboot_component(decrypted_iboot, patched_iboot)

                    im4p = patched_iboot

                # patch kernelcache
                if component == 'RestoreKernelCache':
                    kcache_raw = temp_dir / 'kcache.raw'
                    kcache_patched = temp_dir / 'kcache.patched'
                    kc_bpatch = temp_dir / 'kc.bpatch'
                    im4p_payload = IM4P(im4p.read_bytes()).payload
                    im4p_payload.decompress()
                    kcache_raw.write_bytes(im4p_payload.output().data)
                    self.patch_kernelcache(kcache_raw, kcache_patched)
                    self.create_kernelcache_patch_file(kcache_raw.read_bytes(), kcache_patched.read_bytes(),
                                                       kc_bpatch)
                    patch = kc_bpatch

                # patch RestoreRamDisk
                if component == 'RestoreRamDisk':
                    dmg = temp_dir / 'ramdisk.dmg'
                    im4p = IM4P(local_component.read_bytes())
                    dmg.write_bytes(im4p.payload.output().data)

                    # self.create_img4(im4p, dmg, im4m, img4_get_component_tag(component).decode())

                    if self._hdiutil is None:
                        raise NotImplementedError('missing hdiutil')

                    self._hdiutil('resize', '-size', '256MB', dmg)

                    mountpoint = temp_dir / 'sshrd'
                    mountpoint.mkdir(exist_ok=True, parents=True)
                    self._hdiutil('attach', '-mountpoint', mountpoint, dmg)
                    self._gtar('-x', '--no-overwrite-dir', '-f', self._ramdisk / 'other' / 'ramdisk.tar.gz', '-C',
                               mountpoint)

                    logger.info('extracting Pogo.app/* contents into /usr/local/bin/loader.app/*')
                    local_app = temp_dir / 'Pogo'
                    self._tips.extractall(local_app)
                    loader_app = mountpoint / 'usr' / 'local' / 'bin' / 'loader.app'
                    shutil.rmtree(mountpoint / loader_app)
                    shutil.copytree(local_app / 'Payload' / 'Pogo.app', loader_app)

                    logger.info('renaming /usr/local/bin/loader.app/Pogo -> /usr/local/bin/loader.app/Tips')
                    shutil.move(loader_app / 'Pogo', loader_app / 'Tips')

                    self._hdiutil('detach', '-force', mountpoint)
                    self._hdiutil('resize', '-sectors', 'min', dmg)

                    im4p = dmg

                # create IMG4
                self.create_img4(im4p, img4, im4m, fourcc, patch, wrap=wrap)

    def create_patched_boot(self) -> None:
        logger.info('creating patched boot')

        if self._ipsw is None:
            self._init_ipsw()

        build_identity = self._ipsw.build_manifest.get_build_identity(self._hardware_model)

        self.pwn()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)

            im4m = temp_dir / 'IM4M'
            self._img4tool('-e', '-s', self._shsh_blob, '-m', im4m)

            # use costume RestoreLogo
            self.create_img4(self._palera1n / 'other' / 'bootlogo.im4p', self._boot_dir / 'RestoreLogo.img4', im4m,
                             'rlgo', wrap=True)

            for component in ('iBSS', 'iBEC', 'DeviceTree', 'StaticTrustCache', 'KernelCache'):
                logger.info(f'patching {component}')
                local_component = temp_dir / component
                component_path = build_identity.get_component_path(component)

                if self._devel:
                    if component in ('iBSS', 'iBEC'):
                        component_path = component_path.replace('RELEASE', 'DEVELOPMENT')
                    if component == 'KernelCache':
                        component_path = component_path.replace('release', 'development')

                local_component.write_bytes(self._ipsw.read(component_path))
                img4 = (self._boot_dir / component).with_suffix('.img4')
                im4p_file = local_component

                if component in ('iBSS', 'iBEC'):
                    iboot = local_component
                    iboot_dec = iboot.with_suffix('.dec')
                    iboot_patched = iboot.with_suffix('.patched')
                    boot_args = None
                    self.decrypt(iboot, iboot_dec)
                    if component == 'iBEC':
                        boot_args = '-v keepsyms=1 debug=0x2014e panic-wait-forever=1'
                    self.patch_iboot_component(iboot_dec, iboot_patched, boot_args)
                    self.create_img4(iboot_patched, img4, im4m, component.lower(), wrap=True)

                if component == 'KernelCache':
                    kcache_raw = temp_dir / 'kcache.raw'
                    kernelcache_buf = local_component.read_bytes()
                    kpp_bin = temp_dir / 'kpp.bin'
                    kcache_patched = temp_dir / 'kcache.patched'
                    fourcc = 'rkrn'

                    im4p = IM4P(kernelcache_buf)
                    im4p.payload.decompress()
                    kcache_raw.write_bytes(im4p.payload.output().data)

                    if not self._devel:
                        if self._hardware_model.startswith('iPhone8') or self._hardware_model.startswith('iPad6'):
                            kpp_bin.write_bytes(im4p.payload.extra)

                    if self._devel:
                        self.create_img4(im4p_file, img4, im4m, fourcc, patch=self._bpatch_file)
                    else:
                        self.patch_kernelcache(kcache_raw, kcache_patched, flag_o=True)

                        im4p_file = temp_dir / 'krnlboot.im4p'

                        if self._hardware_model.startswith('iPhone8') or self._hardware_model.startswith('iPad6'):
                            im4p = IM4P(fourcc=fourcc, payload=kcache_patched.read_bytes())
                            im4p.payload.extra = open(kpp_bin, 'rb')
                            im4p.payload.compress(Compression.LZSS)
                            im4p_file.write_bytes(im4p.output())
                        else:
                            im4p = IM4P(fourcc=fourcc, payload=kcache_patched.read_bytes())
                            im4p.payload.compress(Compression.LZSS)
                            im4p_file.write_bytes(im4p.output())

                        self.create_img4(im4p_file, img4, im4m, fourcc)

                if component == 'DeviceTree':
                    self.create_img4(im4p_file, img4, im4m, 'rdtr')

                if component == 'StaticTrustCache':
                    self.create_img4(im4p_file, img4, im4m, 'rtsc')

    def _boot_boot(self) -> None:
        logger.info('booting patched boot image')

        self._gaster('reset')

        # TODO: is really needed?
        time.sleep(1)

        with IRecv() as irecv:
            assert irecv.mode == Mode.DFU_MODE
            logger.info('sending iBSS')
            irecv.send_buffer((self._boot_dir / 'iBSS.img4').read_bytes())

        try:
            with IRecv() as irecv:
                assert irecv.mode == Mode.RECOVERY_MODE_2
                logger.info('sending iBEC')
                irecv.send_buffer((self._boot_dir / 'iBEC.img4').read_bytes())

                if self._chip_id in (0x8010, 0x8015, 0x8011, 0x8012):
                    irecv.send_command('go')
        except USBError:
            # device will reboot and cause a broken pipe
            pass

        with IRecv() as irecv:
            logger.info('sending RestoreLogo')
            irecv.send_buffer((self._boot_dir / 'RestoreLogo.img4').read_bytes())
            irecv.send_command('setpicture 0x1')

            logger.info('sending DeviceTree')
            irecv.send_buffer((self._boot_dir / 'DeviceTree.img4').read_bytes())
            irecv.send_command('devicetree')

            logger.info('sending StaticTrustCache')
            irecv.send_buffer((self._boot_dir / 'StaticTrustCache.img4').read_bytes())
            irecv.send_command('firmware')

            logger.info('sending KernelCache')
            irecv.send_buffer((self._boot_dir / 'KernelCache.img4').read_bytes())
            try:
                irecv.send_command('bootx')
            except USBError:
                pass

    def _boot_ramdisk(self) -> None:
        logger.info('booting ramdisk')

        self._gaster('reset')

        # TODO: is really needed?
        time.sleep(1)

        with IRecv() as irecv:
            assert irecv.mode == Mode.DFU_MODE
            logger.info('sending iBSS')
            irecv.send_buffer((self._ramdisk_dir / 'iBSS.img4').read_bytes())

        try:
            with IRecv() as irecv:
                assert irecv.mode == Mode.RECOVERY_MODE_2
                logger.info('sending iBEC')
                irecv.send_buffer((self._ramdisk_dir / 'iBEC.img4').read_bytes())

                if self._chip_id in (0x8010, 0x8015, 0x8011, 0x8012):
                    irecv.send_command('go')
        except USBError:
            # device will reboot and cause a broken pipe
            pass

        with IRecv() as irecv:
            logger.info('sending RestoreLogo')
            irecv.send_buffer((self._ramdisk_dir / 'RestoreLogo.img4').read_bytes())
            irecv.send_command('setpicture 0x1')

            logger.info('sending RestoreRamDisk')
            irecv.send_buffer((self._ramdisk_dir / 'RestoreRamDisk.img4').read_bytes())
            irecv.send_command('ramdisk')

            time.sleep(2)

            logger.info('sending RestoreDeviceTree')
            irecv.send_buffer((self._ramdisk_dir / 'RestoreDeviceTree.img4').read_bytes())
            irecv.send_command('devicetree')

            logger.info('sending RestoreTrustCache')
            irecv.send_buffer((self._ramdisk_dir / 'RestoreTrustCache.img4').read_bytes())
            irecv.send_command('firmware')

            logger.info('sending RestoreKernelCache')
            irecv.send_buffer((self._ramdisk_dir / 'RestoreKernelCache.img4').read_bytes())
            try:
                irecv.send_command('bootx')
            except USBError:
                pass

    def create_img4(self, im4p: Path, output: Path, im4m: Path, fourcc: str = None, patch: Path = None,
                    wrap=False) -> None:
        args = ['-i', im4p, '-o', output]
        if im4m is not None:
            args += ['-M', im4m]
        if fourcc is not None:
            args += ['-T', fourcc]
        if patch is not None:
            args += ['-P', patch]
        if wrap:
            args += ['-A']
        self._img4(args)

    def reboot(self) -> None:
        try:
            with LockdownClient() as lockdown:
                with DiagnosticsService(lockdown) as diagnostics:
                    diagnostics.restart()
        except NoDeviceConnectedError:
            with IRecv(timeout=1) as irecv:
                irecv.reboot()

    def pwn(self) -> None:
        self._gaster('pwn')

    def decrypt(self, payload: Path, output: Path) -> None:
        self._gaster('decrypt', payload, output)

    def patch_iboot_component(self, iboot: Path, output: Path, boot_args: str = None) -> None:
        if boot_args is None:
            self._iboot64patcher(iboot, output)
        else:
            self._iboot64patcher(iboot, output, '-b', boot_args)

    def patch_kernelcache(self, kernelcache: Path, output: Path, flag_o=False) -> None:
        args = [kernelcache, output, '-a']
        if flag_o:
            args.append('-o')
        self._kernel64patcher(args)

    @staticmethod
    def create_kernelcache_patch_file(original: bytes, patched: bytes, output: Path) -> None:
        result = '#AMFI\n\n'
        for i, _ in enumerate(original):
            if original[i] != patched[i]:
                result += f'{hex(i)} {hex(original[i])} {hex(patched[i])}\n'
        output.write_text(result)

    def enter_dfu(self) -> None:
        while not self.in_dfu:
            print('Prepare to do the following to start enter DFU mode:')
            print(' - Hold VolDown+Power for 5 seconds')
            print(' - Keep holding VolDown for up to 10 seconds')
            input('HIT RETURN TO START> ')
            self.reboot()

            print('[1] Hold VolDown+Power for 5 seconds')
            wait(5)
            print('[2] Keep holding VolDown for up to 10 seconds')
            for _ in trange(10):
                try:
                    with IRecv(timeout=1):
                        pass
                except IRecvNoDeviceConnectedError:
                    continue
                if self.in_dfu:
                    logger.info('device entered DFU')
                    return
            logger.error('Failed to enter DFU')

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} PRODUCT-TYPE:{self._product_type} BOARD-ID:0x{self._board_id:x} ' \
               f'CHIP-ID:0x{self._chip_id:x} MODEL:{self._hardware_model} VERSION:{self._product_version}>'

    def _init_device_info(self) -> None:
        try:
            with LockdownClient() as lockdown:
                self._product_version = lockdown.product_version
                self._board_id = lockdown.board_id
                self._chip_id = lockdown.chip_id
                self._hardware_model = lockdown.hardware_model
                self._product_type = lockdown.product_type
        except (NoDeviceConnectedError, ConnectionFailedError):
            with IRecv(timeout=1) as irecv:
                self._board_id = irecv.board_id
                self._chip_id = irecv.chip_id
                self._hardware_model = irecv.hardware_model
                self._product_type = irecv.product_type

    def _init_ramdisk_ipsw(self) -> None:
        if self._ramdisk_ipsw_path is None:
            devices = list(get_devices(f"'{self._product_type}' == device and '14.8' == version"))
            assert len(devices) == 1
            self._ramdisk_ipsw = IPSW(RemoteZip(devices[0]['url']))
        else:
            self._ramdisk_ipsw = IPSW(ZipFile(self._ramdisk_ipsw_path))

    def _init_ipsw(self) -> None:
        if self._ipsw_path is None:
            devices = list(get_devices(f"'{self._product_type}' == device and '{self._product_version}' == version"))
            assert len(devices) == 1
            self._ipsw = IPSW(RemoteZip(devices[0]['url']))
        else:
            self._ipsw = IPSW(ZipFile(self._ipsw_path))

    @staticmethod
    def _install_pogo(ssh: SSHClient) -> None:
        logger.info('mounting filesystems')
        ssh.exec('/usr/bin/mount_filesystems')

        while True:
            stdin, stdout, stderr = ssh.exec('/bin/ls /mnt2')
            if stdout.read().strip():
                break

        stdin, stdout, stderr = ssh.exec('/usr/bin/find /mnt2/containers/Bundle/Application/ -name Tips.app')
        tips_dir = stdout.read().strip().decode()
        if not tips_dir:
            logger.warning(
                'Tips is not installed. Once your device reboots, install Tips from the App Store and retry')
            ssh.exec('/sbin/reboot')
            return

        logger.info(f'copying /usr/local/bin/loader.app/* -> {tips_dir}/*')
        ssh.exec(f'/bin/cp -rf /usr/local/bin/loader.app/* {tips_dir}')

        logger.info('fixing Tips.app permissions')
        ssh.exec(f'/usr/sbin/chown 33 {tips_dir}/Tips')
        ssh.exec(f'/bin/chmod 755 {tips_dir}/Tips {tips_dir}/PogoHelper')
        ssh.exec(f'/usr/sbin/chown 0 {tips_dir}/PogoHelper')

    @staticmethod
    def _disable_nvram_stuff(ssh: SSHClient) -> None:
        ssh.exec('/usr/sbin/nvram boot-args="-v keepsyms=1 debug=0x2014e launchd_unsecure_cache=1 '
                 'launchd_missing_exec_no_panic=1 amfi=0xff amfi_allow_any_signature=1 '
                 'amfi_get_out_of_my_way=1 amfi_allow_research=1 '
                 'amfi_unrestrict_task_for_pid=1 amfi_unrestricted_local_signing=1 '
                 'cs_enforcement_disable=1 pmap_cs_allow_modified_code_pages=1 pmap_cs_enforce_coretrust=0 '
                 'pmap_cs_unrestrict_pmap_cs_disable=1 -unsafe_kernel_text dtrace_dof_mode=1 '
                 'panic-wait-forever=1 -panic_notify cs_debug=1 PE_i_can_has_debugger=1"')
        ssh.exec('/usr/sbin/nvram allow-root-hash-mismatch=1')
        ssh.exec('/usr/sbin/nvram root-live-fs=1')
        ssh.exec('/usr/sbin/nvram auto-boot=false')

    def _dump_blobs(self, ssh: SSHClient) -> None:
        stdin, stdout, stderr = ssh.exec('cat /dev/rdisk1')
        with tempfile.NamedTemporaryFile('wb', delete=False) as f:
            f.write(stdout.read())
            dump_file = Path(f.name)
        self._img4tool('--convert', '-s', self._shsh_blob, dump_file)
        dump_file.unlink()
