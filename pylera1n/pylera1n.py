import contextlib
import logging
import os
import plistlib
import shutil
import tarfile
import tempfile
import time
from io import BytesIO
from pathlib import Path
from typing import Optional, Generator
from zipfile import ZipFile

import requests
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
from paramiko.config import SSH_PORT
from paramiko.ssh_exception import SSHException
from plumbum import local
from pyimg4 import IM4P, Compression, IMG4
from pyipsw.pyipsw import get_devices
from pylera1n.exceptions import MissingProductVersionError
from pylera1n.sshclient import SSHClient
from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import NoDeviceConnectedError, IRecvNoDeviceConnectedError, ConnectionFailedError
from pymobiledevice3.irecv import IRecv, Mode
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.restore.ipsw.ipsw import IPSW
from remotezip import RemoteZip
from tqdm import trange
from usb import USBError

logger = logging.getLogger(__name__)

OS_VARIANT = os.uname().sysname
DEFAULT_STORAGE = Path('~/.pylera1n').expanduser()
PALERA1N_PATH = Path(__file__).parent / 'palera1n'

blacktop_ipsw = local['ipsw']


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
    pogo = requests.get('https://nightly.link/doronz88/Pogo/workflows/build/master/Pogo.zip').content
    pogo = ZipFile(BytesIO(pogo))
    with pogo.open('Pogo.ipa') as f:
        output.write_bytes(f.read())


@contextlib.contextmanager
def wait_device_ssh() -> Generator[SSHClient, None, None]:
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

    client = None

    while client is None:
        try:
            client = SSHClient(sock)
        except SSHException:
            pass

    try:
        yield client
    finally:
        client.close()


RESTORE_COMPONENTS = ('iBSS', 'iBEC', 'RestoreDeviceTree', 'RestoreRamDisk', 'RestoreTrustCache',
                      'RestoreKernelCache', 'RestoreLogo')

BOOT_COMPONENTS = ('iBSS', 'iBEC', 'DeviceTree', 'StaticTrustCache', 'KernelCache', 'RestoreLogo')


class Pylera1n:
    def __init__(self, product_version: str = None, ramdisk_ipsw: str = None, ipsw: str = None,
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
        self._gaster = local[str(gaster_path)]
        self._iboot64patcher = local[str(PALERA1N_PATH / 'binaries' / OS_VARIANT / 'iBoot64Patcher')]
        self._kernel64patcher = local[str(PALERA1N_PATH / 'binaries' / OS_VARIANT / 'Kernel64Patcher')]
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

        self._kernel_patch_file = Path(
            __file__).parent / 'kernel_patches' / f'{self._product_type}-{self._product_version}.patch'

        shsh_blob_dir = self._storage / 'shsh'
        shsh_blob_dir.mkdir(exist_ok=True, parents=True)
        self._storage_shsh_blob = shsh_blob_dir / f'{self._hardware_model}-{self._product_version}.shsh'

        self._storage_ramdisk_dir = self._storage / 'ramdisk' / self._hardware_model
        self._storage_ramdisk_dir.mkdir(exist_ok=True, parents=True)

        self._storage_boot_dir = self._storage / 'boot' / self._hardware_model / self._product_version
        self._storage_boot_dir.mkdir(exist_ok=True, parents=True)

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

    def jailbreak(self, recreate_ramdisk=False, recreate_boot=False, kernel_patches: Path = None,
                  iboot_patches: Path = None, install_pogo=False) -> None:
        logger.info('jailbreaking')

        if kernel_patches is not None:
            recreate_boot = True

        if iboot_patches is not None:
            recreate_boot = True

        if not self._storage_shsh_blob.exists() or recreate_ramdisk:
            logger.info('creating ramdisk')
            self.boot_ramdisk(recreate_ramdisk)
            self.perform_ramdisk_ssh_operations(dump_blobs=True, install_pogo=install_pogo,
                                                enable_development_options=self._devel is True, reboot=True)

        self.enter_dfu()
        self.pwn()

        if not self.has_prepared_boot or recreate_boot:
            self.create_patched_boot(kernel_patches=kernel_patches, iboot_patches=iboot_patches)

        self._boot_boot()

    def boot_ramdisk(self, recreate_ramdisk=False) -> None:
        """ boot into ramdisk """
        logger.info('waiting for device to enter DFU')
        self.enter_dfu()
        self.pwn()

        if not self.has_prepared_ramdisk or recreate_ramdisk:
            self.create_ramdisk()
        self._boot_ramdisk()

    @property
    def has_prepared_ramdisk(self) -> bool:
        for component in RESTORE_COMPONENTS:
            if not ((self._storage_ramdisk_dir / component).with_suffix('.img4').exists()):
                return False
        return True

    @property
    def has_prepared_boot(self) -> bool:
        for component in BOOT_COMPONENTS:
            if not ((self._storage_boot_dir / component).with_suffix('.img4').exists()):
                return False
        return True

    def perform_ramdisk_ssh_operations(self, dump_blobs=False, install_pogo=False,
                                       enable_development_options=False, auto_boot=False,
                                       reboot=False) -> None:
        """ create blobs, install pogo and patch nvram if on non-rootless """
        with wait_device_ssh() as ssh:
            if dump_blobs:
                ssh.dump_blobs(self._storage_shsh_blob)

            if install_pogo:
                ssh.install_pogo()

            if enable_development_options:
                ssh.enable_development_options()

            ssh.auto_boot = auto_boot

            if reboot:
                ssh.reboot()

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

            with open(PALERA1N_PATH / 'ramdisk' / 'shsh' / f'0x{self._chip_id:x}.shsh', 'rb') as costum_ramdisk:
                im4m = plistlib.load(costum_ramdisk)['ApImg4Ticket']

            build_identity = self._ramdisk_ipsw.build_manifest.get_build_identity(self._hardware_model)

            logger.info('patching RestoreLogo')
            img4_file = self._storage_ramdisk_dir / 'RestoreLogo.img4'
            im4p_file = PALERA1N_PATH / 'other' / 'bootlogo.im4p'
            im4p_file = IM4P(fourcc='rlgo', payload=im4p_file.read_bytes(), description='Unknown')
            img4_file.write_bytes(IMG4(im4p=im4p_file, im4m=im4m).output())

            # extract
            for component in ('iBSS', 'iBEC', 'RestoreDeviceTree', 'RestoreRamDisk', 'RestoreTrustCache',
                              'RestoreKernelCache'):
                logger.info(f'patching {component}')

                local_component = temp_dir / component
                local_component.write_bytes(self._ramdisk_ipsw.read(build_identity.get_component_path(component)))

                im4p_file = local_component
                img4_file = (self._storage_ramdisk_dir / component).with_suffix('.img4')

                if component in ('iBSS', 'iBEC'):
                    iboot = local_component
                    decrypted_iboot = iboot.with_suffix('.dec')
                    self.decrypt(iboot, decrypted_iboot)
                    patched_iboot_file = iboot.with_suffix('.patched')

                    if iboot.parts[-1] == 'iBEC':
                        boot_args = 'rd=md0 debug=0x2014e -v wdt=-1 '
                        if self._chip_id in (0x8960, 0x7000, 0x7001):
                            # TODO: macos variant?
                            boot_args += '-restore'
                        self.patch_iboot_component(decrypted_iboot, patched_iboot_file, boot_args)
                    else:
                        self.patch_iboot_component(decrypted_iboot, patched_iboot_file)

                    fourcc = component.lower()
                    im4p = IM4P(payload=patched_iboot_file.read_bytes(), fourcc=fourcc)
                    img4 = IMG4(im4p=im4p, im4m=im4m)
                    img4_file.write_bytes(img4.output())

                elif component == 'RestoreKernelCache':
                    kcache_raw = temp_dir / 'kcache.raw'
                    kcache_patched = temp_dir / 'kcache.patched'
                    im4p_payload = IM4P(im4p_file.read_bytes()).payload
                    im4p_payload.decompress()
                    kcache_raw.write_bytes(im4p_payload.output().data)
                    self.patch_kernelcache(kcache_raw, kcache_patched)

                    im4p = IM4P(fourcc='rkrn', payload=kcache_patched.read_bytes())
                    im4p.payload.compress(Compression.LZSS)
                    img4 = IMG4(im4p=im4p, im4m=im4m)
                    img4_file.write_bytes(img4.output())

                elif component == 'RestoreRamDisk':
                    dmg = temp_dir / 'ramdisk.dmg'
                    im4p_file = IM4P(local_component.read_bytes())
                    dmg.write_bytes(im4p_file.payload.output().data)

                    if self._hdiutil is None:
                        raise NotImplementedError('missing hdiutil')
                    self._hdiutil('resize', '-size', '256MB', dmg)

                    mountpoint = temp_dir / 'sshrd'
                    mountpoint.mkdir(exist_ok=True, parents=True)
                    self._hdiutil('attach', '-mountpoint', mountpoint, dmg)

                    with tarfile.open(PALERA1N_PATH / 'ramdisk' / 'other' / 'ramdisk.tar.gz') as costum_ramdisk:
                        costum_ramdisk.extractall(mountpoint)

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

                    im4p = IM4P(payload=dmg.read_bytes(), fourcc='rdsk')
                    img4 = IMG4(im4p=im4p, im4m=im4m)
                    img4_file.write_bytes(img4.output())

                elif component == 'RestoreDeviceTree':
                    im4p = IM4P(im4p_file.read_bytes())
                    im4p.fourcc = 'rdtr'
                    img4 = IMG4(im4p=im4p, im4m=im4m)
                    img4_file.write_bytes(img4.output())

                elif component == 'RestoreTrustCache':
                    img4 = IMG4(im4p=im4p_file.read_bytes(), im4m=im4m)
                    img4_file.write_bytes(img4.output())

    def create_patched_boot(self, kernel_patches: Path = None, iboot_patches: Path = None) -> None:
        logger.info('creating patched boot')

        if self._ipsw is None:
            self._init_ipsw()

        if kernel_patches is None:
            if self._kernel_patch_file.exists():
                kernel_patches = self._kernel_patch_file

        build_identity = self._ipsw.build_manifest.get_build_identity(self._hardware_model)

        self.pwn()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)

            im4m = self._storage_shsh_blob.read_bytes()

            # use costume RestoreLogo
            logger.info('patching RestoreLogo')
            img4_file = self._storage_boot_dir / 'RestoreLogo.img4'
            im4p_file = PALERA1N_PATH / 'other' / 'bootlogo.im4p'
            im4p_file = IM4P(fourcc='rlgo', payload=im4p_file.read_bytes(), description='Unknown')
            img4_file.write_bytes(IMG4(im4p=im4p_file, im4m=im4m).output())

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
                img4_file = (self._storage_boot_dir / component).with_suffix('.img4')
                im4p_file = local_component

                if component in ('iBSS', 'iBEC'):
                    iboot = local_component
                    iboot_dec_file = iboot.with_suffix('.dec')
                    patched_iboot_file = iboot.with_suffix('.patched')
                    boot_args = None
                    self.decrypt(iboot, iboot_dec_file)

                    if component == 'iBEC':
                        boot_args = '-v keepsyms=1 debug=0x2014e panic-wait-forever=1'
                        logger.debug(f'adding boot args to iBEC: "{boot_args}"')

                    if iboot_patches is not None:
                        patched_iboot_file.write_bytes(
                            self.patch(iboot_dec_file.read_bytes(), iboot_patches.read_text()))
                    else:
                        self.patch_iboot_component(iboot_dec_file, patched_iboot_file, boot_args)

                    fourcc = component.lower()
                    im4p = IM4P(payload=patched_iboot_file.read_bytes(), fourcc=fourcc)
                    img4 = IMG4(im4p=im4p, im4m=im4m)
                    img4_file.write_bytes(img4.output())

                if component == 'KernelCache':
                    kcache_raw_file = temp_dir / 'kcache.raw'
                    kernelcache_buf = local_component.read_bytes()
                    kpp_bin = temp_dir / 'kpp.bin'
                    kcache_patched_file = temp_dir / 'kcache.patched'
                    fourcc = 'rkrn'

                    im4p = IM4P(kernelcache_buf)
                    im4p.payload.decompress()
                    kcache_raw = im4p.payload.output().data

                    kcache_raw_file.write_bytes(kcache_raw)

                    if not self._devel:
                        if self._hardware_model.startswith('iPhone8') or self._hardware_model.startswith('iPad6'):
                            kpp_bin.write_bytes(im4p.payload.extra)

                    if self._devel:
                        im4p = IM4P(kernelcache_buf)
                        im4p.fourcc = fourcc
                        img4 = IMG4(im4p=im4p, im4m=im4m)
                        img4_file.write_bytes(img4.output())
                    else:
                        if kernel_patches is not None:
                            if kcache_raw.startswith(b'\xca\xfe\xba\xbe'):
                                # trim FAt image header
                                kcache_raw = kcache_raw[0x1c:]

                            logger.debug(f'using kernel patch file: {kernel_patches}')
                            kcache_patched = self.patch(kcache_raw, kernel_patches.read_text())
                        else:
                            self.patch_kernelcache(kcache_raw_file, kcache_patched_file, flag_o=True)
                            kcache_patched = kcache_patched_file.read_bytes()

                        im4p = IM4P(fourcc=fourcc, payload=kcache_patched)
                        im4p.payload.compress(Compression.LZSS)

                        if self._hardware_model.startswith('iPhone8') or self._hardware_model.startswith('iPad6'):
                            im4p.payload.extra = open(kpp_bin, 'rb')

                        img4 = IMG4(im4p=im4p, im4m=im4m)
                        img4_file.write_bytes(img4.output())

                elif component == 'DeviceTree':
                    im4p = IM4P(im4p_file.read_bytes())
                    im4p.fourcc = 'rdtr'
                    img4 = IMG4(im4p=im4p, im4m=im4m)
                    img4_file.write_bytes(img4.output())

                elif component == 'StaticTrustCache':
                    im4p = IM4P(im4p_file.read_bytes())
                    im4p.fourcc = 'rtsc'
                    img4 = IMG4(im4p=im4p, im4m=im4m)
                    img4_file.write_bytes(img4.output())

    def _boot_boot(self) -> None:
        logger.info('booting patched boot image')

        self._gaster('reset')

        # TODO: is really needed?
        time.sleep(1)

        with IRecv() as irecv:
            assert irecv.mode == Mode.DFU_MODE
            logger.info('sending iBSS')
            irecv.send_buffer((self._storage_boot_dir / 'iBSS.img4').read_bytes())

        try:
            with IRecv() as irecv:
                assert irecv.mode == Mode.RECOVERY_MODE_2
                logger.info('sending iBEC')
                irecv.send_buffer((self._storage_boot_dir / 'iBEC.img4').read_bytes())

                if self._chip_id in (0x8010, 0x8015, 0x8011, 0x8012):
                    irecv.send_command('go', b_request=1)
                    irecv.ctrl_transfer(0x21, 1)
        except USBError:
            # device will reboot and cause a broken pipe
            pass

        # waiting for iBoot to load
        logger.info('waiting for iBoot to load')
        wait(3)

        with IRecv() as irecv:
            logger.info('sending RestoreLogo')
            irecv.send_buffer((self._storage_boot_dir / 'RestoreLogo.img4').read_bytes())
            irecv.send_command('setpicture 0x1')

            logger.info('sending DeviceTree')
            irecv.send_buffer((self._storage_boot_dir / 'DeviceTree.img4').read_bytes())
            irecv.send_command('devicetree')

            logger.info('sending StaticTrustCache')
            irecv.send_buffer((self._storage_boot_dir / 'StaticTrustCache.img4').read_bytes())
            irecv.send_command('firmware')

            logger.info('sending KernelCache')
            irecv.send_buffer((self._storage_boot_dir / 'KernelCache.img4').read_bytes())
            try:
                irecv.send_command('bootx', b_request=1)
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
            irecv.send_buffer((self._storage_ramdisk_dir / 'iBSS.img4').read_bytes())

        try:
            with IRecv() as irecv:
                assert irecv.mode == Mode.RECOVERY_MODE_2
                logger.info('sending iBEC')
                irecv.send_buffer((self._storage_ramdisk_dir / 'iBEC.img4').read_bytes())

                if self._chip_id in (0x8010, 0x8015, 0x8011, 0x8012):
                    irecv.send_command('go')
        except USBError:
            # device will reboot and cause a broken pipe
            pass

        with IRecv() as irecv:
            logger.info('sending RestoreLogo')
            irecv.send_buffer((self._storage_ramdisk_dir / 'RestoreLogo.img4').read_bytes())
            irecv.send_command('setpicture 0x1')

            logger.info('sending RestoreRamDisk')
            irecv.send_buffer((self._storage_ramdisk_dir / 'RestoreRamDisk.img4').read_bytes())
            irecv.send_command('ramdisk')

            time.sleep(2)

            logger.info('sending RestoreDeviceTree')
            irecv.send_buffer((self._storage_ramdisk_dir / 'RestoreDeviceTree.img4').read_bytes())
            irecv.send_command('devicetree')

            logger.info('sending RestoreTrustCache')
            irecv.send_buffer((self._storage_ramdisk_dir / 'RestoreTrustCache.img4').read_bytes())
            irecv.send_command('firmware')

            logger.info('sending RestoreKernelCache')
            irecv.send_buffer((self._storage_ramdisk_dir / 'RestoreKernelCache.img4').read_bytes())
            try:
                irecv.send_command('bootx', b_request=1)
            except USBError:
                pass

    @staticmethod
    def reboot() -> None:
        try:
            with LockdownClient() as lockdown:
                lockdown.enter_recovery()
        except NoDeviceConnectedError:
            with IRecv(timeout=1) as irecv:
                irecv.reboot()

    def pwn(self) -> None:
        logger.info('pwn-ing')
        self._gaster('pwn')

    def decrypt(self, payload: Path, output: Path) -> None:
        self._gaster('decrypt', payload, output)

    def patch_iboot_component(self, iboot: Path, output: Path, boot_args: str = None) -> None:
        if boot_args is None:
            self._iboot64patcher(iboot, output)
        else:
            self._iboot64patcher(iboot, output, '-b', boot_args)

    @staticmethod
    def patch(buf: bytes, patches: str) -> bytes:
        patched = buf

        with tempfile.NamedTemporaryFile('wb+', delete=False) as f:
            f.write(buf)
            file = Path(f.name)

        for line in patches.splitlines():
            if ':' not in line:
                continue

            if line.startswith(';') or line.startswith('#'):
                continue

            line = line.strip()

            address, patch = line.split(':', 1)
            retcode, stdout, stderr = blacktop_ipsw['macho', 'a2o', str(file), address].run()
            offset = int(stderr.split('hex=', 1)[1].split(' ', 1)[0], 16)

            ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
            encoding, count = ks.asm(patch)
            encoding = bytes(encoding)
            patched = patched[:offset] + encoding + patched[offset + len(encoding):]

        file.unlink()

        return patched

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
            devices = list(get_devices(f"'{self._product_type}' == device and '15.6' == version"))
            assert len(devices) == 1
            url = devices[0]['url']

            logger.info(f'using remote ipsw: {url}')
            self._ramdisk_ipsw = IPSW(RemoteZip(url))
        else:
            self._ramdisk_ipsw = IPSW(ZipFile(self._ramdisk_ipsw_path))

    def _init_ipsw(self) -> None:
        if self._ipsw_path is None:
            devices = list(get_devices(f"'{self._product_type}' == device and '{self._product_version}' == version"))
            assert len(devices) == 1
            self._ipsw = IPSW(RemoteZip(devices[0]['url']))
        else:
            self._ipsw = IPSW(ZipFile(self._ipsw_path))
