import contextlib
import logging
import os
import plistlib
import shutil
import tarfile
import tempfile
import time
from enum import Enum
from io import BytesIO
from pathlib import Path
from ssl import SSLEOFError
from typing import Optional, Generator
from zipfile import ZipFile

import requests
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
from paramiko.config import SSH_PORT
from paramiko.ssh_exception import SSHException
from plumbum import local
from pyimg4 import IM4P, Compression, IMG4
from pyipsw.pyipsw import get_devices
from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import NoDeviceConnectedError, IRecvNoDeviceConnectedError, ConnectionFailedError, \
    MuxException
from pymobiledevice3.irecv import IRecv, Mode
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.restore.ipsw.ipsw import IPSW
from remotezip import RemoteZip
from tqdm import trange
from usb import USBError

from pylera1n.common import DEFAULT_STORAGE, PALERA1N_PATH, BOOTLOGO_PATH, wait, OS_VARIANT, \
    blacktop_ipsw
from pylera1n.exceptions import MissingProductVersionError
from pylera1n.sshclient import SSHClient

logger = logging.getLogger(__name__)


class KernelcachdStrategy(Enum):
    PongoKpf = 'pongo'
    Normal = 'normal'


def download_gaster(output: Path, os_version: str = os.uname().sysname):
    logger.info('downloading gaster')
    gaster_zip = requests.get(
        f'https://nightly.link/palera1n/gaster/workflows/makefile/main/gaster-{os_version}.zip').content
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
        try:
            sock = device.connect(SSH_PORT)
        except MuxException:
            pass

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


def rm_tree(pth: Path) -> None:
    if not pth.exists():
        return

    for child in pth.glob('*'):
        if child.is_file():
            child.unlink()
        else:
            rm_tree(child)
    pth.rmdir()


RESTORE_COMPONENTS = ('iBSS', 'iBEC', 'RestoreDeviceTree', 'RestoreRamDisk', 'RestoreTrustCache',
                      'RestoreKernelCache', 'RestoreLogo')

BOOT_COMPONENTS = ('iBSS', 'iBEC', 'DeviceTree', 'StaticTrustCache', 'KernelCache', 'RestoreLogo')


class Pylera1n:
    def __init__(self, product_version: str = None, ramdisk_ipsw: str = None, ipsw: str = None,
                 devel=False, storage: Path = DEFAULT_STORAGE):
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
        self._ecid: Optional[str] = None
        self._gaster = local[str(gaster_path)]
        self._hdiutil = None if os.uname().sysname != 'Darwin' else local['hdiutil']
        self._ramdisk_ipsw_path = ramdisk_ipsw
        self._ramdisk_ipsw: Optional[IPSW] = None
        self._ipsw_path = ipsw
        self._boot_ipsw: Optional[IPSW] = None
        self._devel = devel
        self._tips = ZipFile(pogo_path)
        self._init_device_info()

        if self._product_version is None:
            raise MissingProductVersionError()

        self._kernel_patch_file = Path(
            __file__).parent / 'kernel_patches' / f'{self._product_type}-{self._product_version}.patch'

        shsh_blob_dir = self._storage / 'shsh'
        shsh_blob_dir.mkdir(exist_ok=True, parents=True)
        self._storage_shsh_blob = shsh_blob_dir / f'{self._ecid}-{self._hardware_model}-{self._product_version}.der'

        self._storage_ramdisk_dir = self._storage / 'ramdisk' / self._hardware_model

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

    def jailbreak(self, recreate_ramdisk=False, recreate_boot=False, install_pogo=False, fsboot=False,
                  fakefs=False) -> None:
        logger.info('jailbreaking')

        if recreate_boot:
            rm_tree(self._storage_boot_dir)

        kernelcachd = None
        if fsboot:
            kernelcachd = KernelcachdStrategy.PongoKpf

        if not self._storage_shsh_blob.exists() or recreate_ramdisk:
            logger.info('creating ramdisk')
            self.boot_ramdisk(recreate_ramdisk)
            self.perform_ramdisk_ssh_operations(dump_blobs=True, install_pogo=install_pogo,
                                                enable_development_options=self._devel is True, reboot=True,
                                                kernelcachd=kernelcachd, fakefs=fakefs)

        self.enter_dfu()

        if fsboot:
            self._boot_boot_using_fsboot(fakefs=fakefs)
        else:
            self._boot_boot_using_bootx(fakefs=fakefs)

    def boot_ramdisk(self, recreate_ramdisk=False) -> None:
        """ boot into ramdisk """
        logger.info('waiting for device to enter DFU')

        if recreate_ramdisk:
            rm_tree(self._storage_ramdisk_dir)

        self.enter_dfu()
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
                                       enable_development_options=False, kernelcachd: KernelcachdStrategy = None,
                                       auto_boot=False, reboot=False, fakefs=False) -> None:
        """ create blobs, install pogo and patch nvram if on non-rootless """
        with wait_device_ssh() as ssh:
            ssh.mount_filesystems()

            if dump_blobs:
                logger.info(f'saving apticket to: {self._storage_shsh_blob}')
                self._storage_shsh_blob.write_bytes(ssh.apticket)

            if install_pogo:
                ssh.install_pogo()

            if enable_development_options:
                ssh.enable_development_options()

            if fakefs:
                ssh.create_fakefs()

            if kernelcachd == KernelcachdStrategy.Normal:
                logger.info('placing kernelcachd')
                remote_kernelcachd = ssh.active_preboot / 'System' / 'Library' / 'Caches' / 'com.apple.kernelcaches' / 'kernelcachd'
                ssh.put_file(
                    self._get_boot_component('KernelCache', basename='krnl', is_restore=False, cache=False),
                    remote_kernelcachd)
                ssh.chmod(remote_kernelcachd, 0o644)

            if kernelcachd == KernelcachdStrategy.PongoKpf:
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_dir = Path(temp_dir)

                    local_kernelcache = temp_dir / 'KernelCache.im4p'
                    build_identity = self.boot_ipsw.build_manifest.get_build_identity(self._hardware_model)
                    component_path = build_identity.get_component_path('KernelCache')
                    local_kernelcache.write_bytes(self.boot_ipsw.read(component_path))
                    ssh.place_kernelcachd_using_pongo_kpf(local_kernelcache)

            ssh.auto_boot = auto_boot

            if reboot:
                ssh.reboot()

    @property
    def ramdisk_ipsw(self) -> IPSW:
        if self._ramdisk_ipsw is None:
            self._init_ramdisk_ipsw()
        return self._ramdisk_ipsw

    @property
    def _ramdisk_im4m(self) -> bytes:
        with open(PALERA1N_PATH / 'ramdisk' / 'shsh' / f'0x{self._chip_id:x}.shsh', 'rb') as costume_ramdisk:
            return plistlib.load(costume_ramdisk)['ApImg4Ticket']

    @property
    def _ramdisk_restore_logo(self) -> Path:
        img4_file = self._storage_ramdisk_dir / 'RestoreLogo.img4'
        if img4_file.exists():
            return img4_file

        logger.info('creating restore logo (ramdisk)')

        im4p_file = IM4P(fourcc='logo', payload=BOOTLOGO_PATH.read_bytes(), description='EmbeddedImages-121.100.10')
        img4_file.write_bytes(IMG4(im4p=im4p_file, im4m=self._ramdisk_im4m).output())

        return img4_file

    def _get_ramdisk_component(self, component: str) -> Path:
        img4_file = (self._storage_ramdisk_dir / component).with_suffix('.img4')
        if img4_file.exists():
            return img4_file

        logger.info(f'creating {component} (ramdisk)')

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)

            build_identity = self.ramdisk_ipsw.build_manifest.get_build_identity(self._hardware_model)

            im4p_file = temp_dir / component
            im4p_file.write_bytes(self.ramdisk_ipsw.read(build_identity.get_component_path(component)))
            self._patch_ramdisk_component(component, im4p_file, img4_file)
            return img4_file

    def _patch_ramdisk_component(self, component: str, im4p_file: Path, img4_file: Path) -> None:
        {
            'iBSS': self._patch_ramdisk_ibss,
            'iBEC': self._patch_ramdisk_ibec,
            'RestoreKernelCache': self._patch_ramdisk_restore_kernel_cache,
            'RestoreRamDisk': self._patch_ramdisk_restore_ramdisk,
            'RestoreDeviceTree': self._patch_ramdisk_device_tree,
            'RestoreTrustCache': self._patch_ramdisk_restore_trust_cache,
        }[component](im4p_file, img4_file)

    def _patch_ramdisk_ibss(self, im4p_file: Path, img4_file: Path) -> None:
        decrypted_iboot = im4p_file.with_suffix('.dec')
        self.decrypt(im4p_file, decrypted_iboot)
        patched_iboot_file = im4p_file.with_suffix('.patched')
        self.patch_iboot_component(decrypted_iboot, patched_iboot_file)

        im4p = IM4P(payload=patched_iboot_file.read_bytes(), fourcc='ibss')
        img4 = IMG4(im4p=im4p, im4m=self._ramdisk_im4m)
        img4_file.write_bytes(img4.output())

    def _patch_ramdisk_ibec(self, im4p_file: Path, img4_file: Path) -> None:
        decrypted_iboot = im4p_file.with_suffix('.dec')
        self.decrypt(im4p_file, decrypted_iboot)
        patched_iboot_file = im4p_file.with_suffix('.patched')

        boot_args = 'rd=md0 debug=0x2014e -v wdt=-1 '
        if self._chip_id in (0x8960, 0x7000, 0x7001):
            # TODO: macos variant?
            boot_args += '-restore'
        self.patch_iboot_component(decrypted_iboot, patched_iboot_file, boot_args)

        im4p = IM4P(payload=patched_iboot_file.read_bytes(), fourcc='ibec')
        img4 = IMG4(im4p=im4p, im4m=self._ramdisk_im4m)
        img4_file.write_bytes(img4.output())

    def _patch_ramdisk_restore_kernel_cache(self, im4p_file: Path, img4_file: Path) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            kcache_raw = temp_dir / 'kcache.raw'
            kcache_patched = temp_dir / 'kcache.patched'
            im4p_payload = IM4P(im4p_file.read_bytes()).payload
            im4p_payload.decompress()
            kcache_raw.write_bytes(im4p_payload.output().data)
            self.patch_kernelcache(kcache_raw, kcache_patched)

            im4p = IM4P(fourcc='rkrn', payload=kcache_patched.read_bytes())
            im4p.payload.compress(Compression.LZSS)
            img4 = IMG4(im4p=im4p, im4m=self._ramdisk_im4m)
            img4_file.write_bytes(img4.output())

    def _patch_ramdisk_restore_ramdisk(self, im4p_file: Path, img4_file: Path) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            dmg = temp_dir / 'ramdisk.dmg'
            im4p_file = IM4P(im4p_file.read_bytes())
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
            try:
                shutil.rmtree(mountpoint / loader_app)
            except FileNotFoundError:
                pass
            shutil.copytree(local_app / 'Payload' / 'Pogo.app', loader_app)

            logger.info('renaming /usr/local/bin/loader.app/Pogo -> /usr/local/bin/loader.app/Tips')
            shutil.move(loader_app / 'Pogo', loader_app / 'Tips')

            self._hdiutil('detach', '-force', mountpoint)
            self._hdiutil('resize', '-sectors', 'min', dmg)

            im4p = IM4P(payload=dmg.read_bytes(), fourcc='rdsk')
            img4 = IMG4(im4p=im4p, im4m=self._ramdisk_im4m)
            img4_file.write_bytes(img4.output())

    def _patch_ramdisk_device_tree(self, im4p_file: Path, img4_file: Path) -> None:
        im4p = IM4P(im4p_file.read_bytes())
        im4p.fourcc = 'rdtr'
        img4 = IMG4(im4p=im4p, im4m=self._ramdisk_im4m)
        img4_file.write_bytes(img4.output())

    def _patch_ramdisk_restore_trust_cache(self, im4p_file: Path, img4_file: Path) -> None:
        img4 = IMG4(im4p=im4p_file.read_bytes(), im4m=self._ramdisk_im4m)
        img4_file.write_bytes(img4.output())

    @property
    def boot_ipsw(self) -> IPSW:
        if self._boot_ipsw is None:
            self._init_boot_ipsw()
        return self._boot_ipsw

    @property
    def _boot_im4m(self) -> bytes:
        return self._storage_shsh_blob.read_bytes()

    @property
    def _boot_restore_logo(self) -> Path:
        img4_file = self._storage_boot_dir / 'RestoreLogo.img4'
        if img4_file.exists():
            return img4_file

        logger.info('creating restore logo (boot)')

        im4p_file = IM4P(fourcc='logo', payload=BOOTLOGO_PATH.read_bytes(), description='EmbeddedImages-121.100.10')
        img4_file.write_bytes(IMG4(im4p=im4p_file, im4m=self._boot_im4m).output())

        return img4_file

    def _get_boot_component(self, component: str, basename: str = None, cache=True, **kwargs) -> Path:
        if basename is None:
            img4_file = (self._storage_boot_dir / component).with_suffix('.img4')
        else:
            img4_file = (self._storage_boot_dir / basename).with_suffix('.img4')

        if cache and img4_file.exists():
            return img4_file

        logger.info(f'creating {component} (boot)')

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)

            build_identity = self.boot_ipsw.build_manifest.get_build_identity(self._hardware_model)
            component_path = build_identity.get_component_path(component)

            if self._devel:
                if component_path in ('iBSS', 'iBEC'):
                    component_path = component_path.replace('RELEASE', 'DEVELOPMENT')
                elif component_path == 'KernelCache':
                    component_path = component_path.replace('release', 'development')

            im4p_file = temp_dir / component
            im4p_file.write_bytes(self.boot_ipsw.read(component_path))
            self._patch_boot_component(component, im4p_file, img4_file, **kwargs)
            return img4_file

    def _patch_boot_component(self, component: str, im4p_file: Path, img4_file: Path, **kwargs) -> None:
        {
            'iBSS': self._patch_boot_ibss,
            'iBEC': self._patch_boot_ibec,
            'iBoot': self._patch_boot_iboot,
            'KernelCache': self._patch_boot_kernel_cache,
            'DeviceTree': self._patch_boot_device_tree,
            'StaticTrustCache': self._patch_boot_static_trust_cache,
        }[component](im4p_file, img4_file, **kwargs)

    def _patch_boot_ibss(self, im4p_file: Path, img4_file: Path) -> None:
        iboot_dec_file = im4p_file.with_suffix('.dec')
        patched_iboot_file = im4p_file.with_suffix('.patched')
        boot_args = None
        self.decrypt(im4p_file, iboot_dec_file)
        self.patch_iboot_component(iboot_dec_file, patched_iboot_file, boot_args)

        im4p = IM4P(payload=patched_iboot_file.read_bytes(), fourcc='ibss')
        img4 = IMG4(im4p=im4p, im4m=self._boot_im4m)
        img4_file.write_bytes(img4.output())

    def _patch_boot_ibec(self, im4p_file: Path, img4_file: Path) -> None:
        iboot_dec_file = im4p_file.with_suffix('.dec')
        patched_iboot_file = im4p_file.with_suffix('.patched')
        self.decrypt(im4p_file, iboot_dec_file)
        self.patch_iboot_component(iboot_dec_file, patched_iboot_file,
                                   '-v keepsyms=1 debug=0x2014e panic-wait-forever=1')
        im4p = IM4P(payload=patched_iboot_file.read_bytes(), fourcc='ibec')
        img4 = IMG4(im4p=im4p, im4m=self._boot_im4m)
        img4_file.write_bytes(img4.output())

    def _patch_boot_iboot(self, im4p_file: Path, img4_file: Path, fakefs=False) -> None:
        iboot_dec_file = im4p_file.with_suffix('.dec')
        patched_iboot_file = im4p_file.with_suffix('.patched')
        self.decrypt(im4p_file, iboot_dec_file)
        boot_args = '-v keepsyms=1 debug=0x2014e'
        if fakefs:
            boot_args += ' rd=disk0s1s8'
        self.patch_iboot_component(iboot_dec_file, patched_iboot_file, boot_args, fsboot=True)
        patched_iboot_file.write_bytes(patched_iboot_file.read_bytes().replace(b'/kernelcache', b'/kernelcachd'))
        if 0x8010 <= self._chip_id <= 0x801f:
            fourcc = 'ibss'
        else:
            fourcc = 'ibec'
        im4p = IM4P(payload=patched_iboot_file.read_bytes(), fourcc=fourcc, description='Unknown')
        img4 = IMG4(im4p=im4p, im4m=self._boot_im4m)
        img4_file.write_bytes(img4.output())

    def _patch_boot_kernel_cache(self, im4p_file: Path, img4_file: Path, is_restore=True) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            kcache_raw_file = temp_dir / 'kcache.raw'
            kernelcache_buf = im4p_file.read_bytes()
            kcache_patched_file = temp_dir / 'kcache.patched'
            fourcc = 'rkrn' if is_restore else 'krnl'

            im4p = IM4P(kernelcache_buf)
            kpp = im4p.payload.extra
            im4p.payload.decompress()
            kcache_raw = im4p.payload.output().data

            kcache_raw_file.write_bytes(kcache_raw)

            if self._devel:
                im4p = IM4P(kernelcache_buf)
                im4p.fourcc = fourcc
                img4 = IMG4(im4p=im4p, im4m=self._boot_im4m)
                img4_file.write_bytes(img4.output())
            else:
                if self._kernel_patch_file.exists():
                    if kcache_raw.startswith(b'\xca\xfe\xba\xbe'):
                        # trim FAT image header
                        kcache_raw = kcache_raw[0x1c:]

                    logger.debug(f'using kernel patch file: {self._kernel_patch_file}')
                    kcache_patched = self.patch(kcache_raw, self._kernel_patch_file.read_text())
                else:
                    self.patch_kernelcache(kcache_raw_file, kcache_patched_file, flag_o=True)
                    kcache_patched = kcache_patched_file.read_bytes()

                im4p = IM4P(fourcc=fourcc, payload=kcache_patched)
                im4p.payload.compress(Compression.LZSS)
                im4p.payload.extra = kpp

                img4 = IMG4(im4p=im4p, im4m=self._boot_im4m)
                img4_file.write_bytes(img4.output())

    def _patch_boot_device_tree(self, im4p_file: Path, img4_file: Path) -> None:
        im4p = IM4P(im4p_file.read_bytes())
        im4p.fourcc = 'rdtr'
        img4 = IMG4(im4p=im4p, im4m=self._boot_im4m)
        img4_file.write_bytes(img4.output())

    def _patch_boot_static_trust_cache(self, im4p_file: Path, img4_file: Path) -> None:
        im4p = IM4P(im4p_file.read_bytes())
        im4p.fourcc = 'rtsc'
        img4 = IMG4(im4p=im4p, im4m=self._boot_im4m)
        img4_file.write_bytes(img4.output())

    def _boot_boot_using_bootx(self, fakefs=False) -> None:
        self._storage_boot_dir.mkdir(exist_ok=True, parents=True)

        logger.info('booting patched boot image (bootx)')

        self._gaster_pwn()

        ibss = self._get_boot_component('iBSS')

        basename = 'iBEC'
        if fakefs:
            basename += '-fakefs'
        basename += '.img4'
        ibec = self._get_boot_component('iBEC', basename=basename)

        self._gaster_reset()

        restore_logo = self._boot_restore_logo
        device_tree = self._get_boot_component('DeviceTree')
        trust_cache = self._get_boot_component('StaticTrustCache')
        kernel_cache = self._get_boot_component('KernelCache')

        with IRecv() as irecv:
            assert irecv.mode == Mode.DFU_MODE
            logger.info('sending iBSS')
            irecv.send_buffer(ibss.read_bytes())

        try:
            with IRecv() as irecv:
                assert irecv.mode == Mode.RECOVERY_MODE_2

                logger.info('sending iBEC')
                irecv.send_buffer(ibec.read_bytes())

                if self._chip_id in (0x8010, 0x8015, 0x8011, 0x8012):
                    irecv.send_command('go', b_request=1)
                    irecv.ctrl_transfer(0x21, 1)
        except USBError:
            # device will reboot and cause a broken pipe
            pass

        time.sleep(1)

        with IRecv() as irecv:
            logger.info('sending RestoreLogo')
            irecv.send_buffer(restore_logo.read_bytes())
            irecv.send_command('setpicture 0x1')

            logger.info('sending DeviceTree')
            irecv.send_buffer(device_tree.read_bytes())
            irecv.send_command('devicetree')

            logger.info('sending StaticTrustCache')
            irecv.send_buffer(trust_cache.read_bytes())
            irecv.send_command('firmware')

            logger.info('sending KernelCache')
            irecv.send_buffer(kernel_cache.read_bytes())
            try:
                logger.info('booting into ramdisk (boot image)')
                irecv.send_command('bootx', b_request=1)
            except USBError:
                pass

    def _boot_boot_using_fsboot(self, fakefs=False) -> None:
        self._storage_boot_dir.mkdir(exist_ok=True, parents=True)

        logger.info(f'booting patched boot image (fsboot) (fakefs: {fakefs})')

        self._gaster_pwn()

        ibss = None

        if not (0x8010 <= self._chip_id <= 0x801f):
            ibss = self._get_boot_component('iBSS')

        basename = 'iBoot'
        if fakefs:
            basename += '-fakefs'
        basename += '.img4'
        iboot = self._get_boot_component('iBoot', basename=basename, fakefs=fakefs)

        self._gaster_reset()

        if ibss is not None:
            with IRecv() as irecv:
                logger.info('sending iBSS')
                irecv.send_buffer(ibss.read_bytes())
                time.sleep(1)

            with IRecv() as irecv:
                assert irecv.mode == Mode.RECOVERY_MODE_2

        with IRecv() as irecv:
            logger.info('sending iBoot')
            irecv.send_buffer(iboot.read_bytes())
            time.sleep(1)

        with IRecv() as irecv:
            try:
                logger.info('booting into fs')
                irecv.send_command('fsboot')
            except USBError:
                pass

    def _boot_ramdisk(self) -> None:
        self._storage_ramdisk_dir.mkdir(exist_ok=True, parents=True)

        logger.info('booting ramdisk')

        self._gaster_pwn()

        ibss = self._get_ramdisk_component('iBSS')
        ibec = self._get_ramdisk_component('iBEC')

        self._gaster_reset()

        restore_logo = self._ramdisk_restore_logo
        ramdisk = self._get_ramdisk_component('RestoreRamDisk')
        device_tree = self._get_ramdisk_component('RestoreDeviceTree')
        trust_cache = self._get_ramdisk_component('RestoreTrustCache')
        kernel_cache = self._get_ramdisk_component('RestoreKernelCache')

        with IRecv() as irecv:
            assert irecv.mode == Mode.DFU_MODE
            logger.info('sending iBSS')
            irecv.send_buffer(ibss.read_bytes())
            time.sleep(1)

        try:
            with IRecv() as irecv:
                assert irecv.mode == Mode.RECOVERY_MODE_2
                logger.info('sending iBEC')
                irecv.send_buffer(ibec.read_bytes())

                if self._chip_id in (0x8010, 0x8015, 0x8011, 0x8012):
                    irecv.send_command('go', b_request=1)
        except USBError:
            # device will reboot and cause a broken pipe
            pass

        logger.info('Waiting for iBEC to load')
        wait(3)

        with IRecv() as irecv:
            logger.info('sending RestoreLogo')
            irecv.send_buffer(restore_logo.read_bytes())
            irecv.send_command('setpicture 0x1')

            logger.info('sending RestoreRamDisk')
            irecv.send_buffer(ramdisk.read_bytes())
            irecv.send_command('ramdisk')

            time.sleep(2)

            logger.info('sending RestoreDeviceTree')
            irecv.send_buffer(device_tree.read_bytes())
            irecv.send_command('devicetree')

            logger.info('sending RestoreTrustCache')
            irecv.send_buffer(trust_cache.read_bytes())
            irecv.send_command('firmware')

            logger.info('sending RestoreKernelCache')
            irecv.send_buffer(kernel_cache.read_bytes())
            try:
                logger.info('booting into ramdisk (ramdisk image)')
                irecv.send_command('bootx', b_request=1)
            except USBError:
                pass

    @staticmethod
    def reboot() -> None:
        try:
            with LockdownClient() as lockdown:
                lockdown.enter_recovery()
        except (NoDeviceConnectedError, SSLEOFError):
            with IRecv(timeout=3) as irecv:
                irecv.reboot()

    def _gaster_pwn(self) -> None:
        logger.info('gaster pwn')
        self._gaster('pwn')
        time.sleep(1)

    def _gaster_reset(self) -> None:
        logger.info('gaster reset')
        self._gaster('reset')
        time.sleep(1)

    def decrypt(self, payload: Path, output: Path) -> None:
        self._gaster('decrypt', payload, output)

    @staticmethod
    def patch_iboot_component(iboot: Path, output: Path, boot_args: str = None, fsboot=False) -> None:
        executable = str(PALERA1N_PATH / 'binaries' / OS_VARIANT / 'iBoot64Patcher')
        args = [iboot, output]

        if boot_args is not None:
            args += ['-b', boot_args]

        if fsboot:
            args += ['-f']

        local[executable](args)

    @staticmethod
    def patch_kernelcache(kernelcache: Path, output: Path, flag_o=False) -> None:
        args = [kernelcache, output, '-a']
        if flag_o:
            args.append('-o')
        local[str(PALERA1N_PATH / 'binaries' / OS_VARIANT / 'Kernel64Patcher')](args)

    @staticmethod
    def create_kernelcache_patch_file(original: bytes, patched: bytes, output: Path) -> None:
        result = '#AMFI\n\n'
        for i, _ in enumerate(original):
            if original[i] != patched[i]:
                result += f'{hex(i)} {hex(original[i])} {hex(patched[i])}\n'
        output.write_text(result)

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

    def enter_dfu(self) -> None:
        while not self.in_dfu:
            print('Prepare to do the following to start enter DFU mode:')
            print(' - Hold VolDown+Power for 4 seconds (Start only when prompted to!)')
            print(' - Keep holding VolDown for up to 10 seconds')
            input('HIT RETURN TO START> ')
            self.reboot()

            print('[1] Hold VolDown+Power for 4 seconds')
            wait(4)
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
                self._ecid = lockdown.ecid

                logger.info('entering recovery')
                lockdown.enter_recovery()
                wait(3)
        except (NoDeviceConnectedError, ConnectionFailedError):
            with IRecv(timeout=1) as irecv:
                self._board_id = irecv.board_id
                self._chip_id = irecv.chip_id
                self._hardware_model = irecv.hardware_model
                self._product_type = irecv.product_type
                self._ecid = irecv.ecid
        logger.info(f'init with device: {self}')

    def _init_ramdisk_ipsw(self) -> None:
        if self._ramdisk_ipsw_path is None:
            devices = list(get_devices(f"'{self._product_type}' == device and '15.6.1' == version"))
            assert len(devices) == 1
            url = devices[0]['url']

            logger.info(f'using remote ipsw: {url}')
            self._ramdisk_ipsw = IPSW(RemoteZip(url))
        else:
            self._ramdisk_ipsw = IPSW(ZipFile(self._ramdisk_ipsw_path))

    def _init_boot_ipsw(self) -> None:
        if self._ipsw_path is None:
            devices = list(get_devices(f"'{self._product_type}' == device and '{self._product_version}' == version"))
            assert len(devices) == 1
            self._boot_ipsw = IPSW(RemoteZip(devices[0]['url']))
        else:
            self._boot_ipsw = IPSW(ZipFile(self._ipsw_path))
