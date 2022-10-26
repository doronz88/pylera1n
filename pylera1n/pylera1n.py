import contextlib
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
from plumbum import local, FG
from pyimg4 import IM4P
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

from pylera1n.palera1n.sshclient import SSHClient

logger = logging.getLogger(__name__)

OS_VARIANT = os.uname().sysname
DEFAULT_STORAGE = Path('~/.pylera1n').expanduser()


def wait(seconds: int) -> None:
    for _ in trange(seconds):
        time.sleep(1)


def download_gaster(output: Path, os_version: str = os.uname().sysname):
    gaster_zip = requests.get(
        f'https://nightly.link/verygenericname/gaster/workflows/makefile/main/gaster-{os_version}.zip').content
    gaster_zip = ZipFile(BytesIO(gaster_zip))
    with gaster_zip.open('gaster') as f:
        output.write_bytes(f.read())
        output.chmod(0o755)


def download_pogo(output: Path) -> None:
    pogo = requests.get('https://nightly.link/elihwyma/Pogo/workflows/build/root/Pogo.zip').content
    pogo = ZipFile(BytesIO(pogo))
    with pogo.open('Pogo.ipa') as f:
        output.write_bytes(f.read())


class Pylera1n:
    def __init__(self, palera1n: Path, product_version: str = None, ipsw_path: str = None,
                 rootless=True, storage: Path = DEFAULT_STORAGE):
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
        self._hardware_model = None
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
        self._ipsw_path = ipsw_path
        self._ipsw: Optional[IPSW] = None
        self._rootless = rootless
        self._tips = ZipFile(pogo_path)
        self._init_device_info()
        self._init_ipsw()

        shsh_blob_dir = self._storage / 'shsh'
        shsh_blob_dir.mkdir(exist_ok=True, parents=True)
        self._shsh_blob = shsh_blob_dir / f'{self._hardware_model}-{self._product_version}.shsh'

    @property
    def in_dfu(self) -> bool:
        try:
            with LockdownClient():
                return False
        except NoDeviceConnectedError:
            with IRecv(timeout=1) as irecv:
                return irecv.mode == Mode.DFU_MODE

    def exploit(self) -> None:
        if not self._shsh_blob.exists():
            self.boot_ramdisk()
            self.dump_blobs()

    def boot_ramdisk(self) -> None:
        if self._product_version is None:
            raise Exception('cannot exploit without product_version')
        logger.info('waiting for device to enter DFU')
        self.enter_dfu()
        logger.info('pwn-ing device')
        self.pwn()

        with self.create_ramdisk() as ramdisk:
            self.boot(ramdisk)

    def dump_blobs(self) -> None:
        device = None

        while device is None:
            # wait for device to boot
            device = usbmux.select_device()

        sock = None
        while sock is None:
            # wait for ssh server to start
            sock = device.connect(SSH_PORT)

        with SSHClient(sock) as ssh:
            stdin, stdout, stderr = ssh.exec('cat /dev/rdisk1')
            with tempfile.NamedTemporaryFile('wb', delete=False) as f:
                f.write(stdout.read())
                dump_file = Path(f.name)

        self._img4tool('--convert', '-s', self._storage / f'{self._hardware_model}-{self._product_version}.shsh',
                       dump_file)
        dump_file.unlink()

    @contextlib.contextmanager
    def create_ramdisk(self) -> None:
        logger.info('creating ramdisk')

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            local_build_manifest = temp_dir / 'BuildManifest.plist'
            local_build_manifest.write_bytes(self._ipsw.read('BuildManifest.plist'))

            im4m = temp_dir / 'IM4M'
            self._img4tool('-e', '-s', self._ramdisk / 'shsh' / f'0x{self._chip_id:x}.shsh', '-m', im4m)
            build_identity = self._ipsw.build_manifest.get_build_identity(self._hardware_model)

            # use costume RestoreLogo
            self.create_img4(self._palera1n / 'other' / 'bootlogo.im4p', temp_dir / 'bootlogo.img4', im4m,
                             img4_get_component_tag('RestoreLogo').decode(), wrap=True)

            # extract
            for component in ('iBSS', 'iBEC', 'RestoreDeviceTree', 'RestoreRamDisk', 'RestoreTrustCache',
                              'RestoreKernelCache'):
                local_component = temp_dir / component
                local_component.write_bytes(self._ipsw.read(build_identity.get_component_path(component)))

                im4p = local_component
                img4 = local_component.with_suffix('.img4')
                fourcc = img4_get_component_tag(component).decode()
                im4m = temp_dir / 'IM4M'
                patch = None
                wrap = component in ('iBSS', 'iBEC', 'RestoreRamDisk')

                # patch bootloader
                if component in ('iBSS', 'iBEC'):
                    iboot = temp_dir / component
                    decrypted_iboot = iboot.with_suffix('.dec')
                    self.decrypt(iboot, decrypted_iboot)
                    patched_iboot = iboot.with_suffix('.patched')

                    if iboot.parts[-1] == 'iBEC':
                        self.patch_iboot_component(decrypted_iboot, patched_iboot)
                    else:
                        boot_args = 'rd=md0 debug=0x2014e -v wdt=-1 '
                        if self._chip_id in (0x8960, 0x7000, 0x7001):
                            # TODO: macos variant?
                            boot_args += '-restore'
                        self.patch_iboot_component(decrypted_iboot, patched_iboot, boot_args)

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
                    mountpoint.mkdir()
                    self._hdiutil('attach', '-mountpoint', mountpoint, dmg)
                    self._gtar('-x', '--no-overwrite-dir', '-f', self._ramdisk / 'other' / 'ramdisk.tar.gz', '-C',
                               mountpoint)

                    if not self._rootless:
                        # patch Tips app
                        local_app = temp_dir / 'Pogo'
                        self._tips.extractall(local_app)
                        loader_app = mountpoint / 'usr' / 'local' / 'bin' / 'loader.app'
                        shutil.rmtree(mountpoint / loader_app)
                        shutil.copytree(local_app / 'Payload' / 'Pogo.app', loader_app)
                        shutil.move(loader_app / 'Pogo', loader_app / 'Tips')

                    self._hdiutil('detach', '-force', mountpoint)
                    self._hdiutil('resize', '-sectors', 'min', dmg)

                    im4p = dmg

                # create IMG4
                self.create_img4(im4p, img4, im4m, fourcc, patch, wrap=wrap)

            yield temp_dir

    def boot(self, ramdisk: Path) -> None:
        logger.info('booting ramdisk')

        self._gaster('reset')

        # TODO: is really needed?
        time.sleep(1)

        with IRecv() as irecv:
            assert irecv.mode == Mode.DFU_MODE
            logger.info('sending iBSS')
            irecv.send_buffer((ramdisk / 'iBSS.img4').read_bytes())

        try:
            with IRecv() as irecv:
                assert irecv.mode == Mode.RECOVERY_MODE_2
                logger.info('sending iBEC')
                irecv.send_buffer((ramdisk / 'iBEC.img4').read_bytes())

                if self._chip_id in (0x8010, 0x8015, 0x8011, 0x8012):
                    irecv.send_command('go')
        except USBError:
            # device will reboot and cause a broken pipe
            pass

        with IRecv() as irecv:
            logger.info('sending RestoreLogo')
            irecv.send_buffer((ramdisk / 'bootlogo.img4').read_bytes())
            irecv.send_command('setpicture 0x1')

            logger.info('sending RestoreRamDisk')
            irecv.send_buffer((ramdisk / 'RestoreRamDisk.img4').read_bytes())
            irecv.send_command('ramdisk')

            time.sleep(2)

            logger.info('sending RestoreDeviceTree')
            irecv.send_buffer((ramdisk / 'RestoreDeviceTree.img4').read_bytes())
            irecv.send_command('devicetree')

            logger.info('sending RestoreTrustCache')
            irecv.send_buffer((ramdisk / 'RestoreTrustCache.img4').read_bytes())
            irecv.send_command('firmware')

            logger.info('sending RestoreKernelCache')
            irecv.send_buffer((ramdisk / 'RestoreKernelCache.img4').read_bytes())
            try:
                irecv.send_command('bootx')
            except USBError:
                pass

    def create_img4(self, imp4: Path, output: Path, im4m: Path, fourcc: str = None, patch: Path = None,
                    wrap=True) -> None:
        args = ['-i', imp4, '-o', output]
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

    def patch_kernelcache(self, kernelcache: Path, output: Path) -> None:
        self._kernel64patcher(kernelcache, output, '-a')

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

    def _init_ipsw(self) -> None:
        if self._ipsw_path is None:
            devices = list(get_devices(f"'{self._product_type}' == device and '{self._product_version}' == version"))
            assert len(devices) == 1
            self._ipsw = IPSW(RemoteZip(devices[0]['url']))
        else:
            self._ipsw = IPSW(ZipFile(self._ipsw_path))
