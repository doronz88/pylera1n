import logging
from pathlib import Path

import click
import coloredlogs
from pymobiledevice3.exceptions import IRecvNoDeviceConnectedError

import pylera1n
from pylera1n.exceptions import MissingProductVersionError
from pylera1n.pylera1n import Pylera1n, wait_device_ssh

coloredlogs.install(level=logging.INFO)

logger = logging.getLogger(__name__)
logging.getLogger('paramiko.transport').disabled = True
logging.getLogger('pymobiledevice3.irecv').disabled = True
logging.getLogger('urllib3.connectionpool').disabled = True

PALERA1N_PATH = Path(pylera1n.__file__).parent / 'palera1n'


class Command(click.Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params[:0] = [
            click.Option(('debug', '-d', '--debug'), callback=self.enable_debug, expose_value=False, is_eager=False,
                         is_flag=True),
        ]

    @staticmethod
    def enable_debug(ctx, param, value):
        if value:
            coloredlogs.set_level(logging.DEBUG)


@click.group()
def cli():
    pass


@cli.command(cls=Command)
def ssh():
    """ Connect via ssh """
    with wait_device_ssh() as ssh:
        ssh.interact()


@cli.command(cls=Command)
@click.argument('source', type=click.Path(file_okay=True, dir_okay=False, exists=True))
@click.argument('destination')
def put_file(source, destination):
    """ Put file over ssh """
    with wait_device_ssh() as ssh:
        ssh.put_file(source, destination)


@cli.command(cls=Command)
@click.option('-v', '--version', help='iOS version. Can be queried automatically when device is in Normal mode')
@click.option('--ramdisk-ipsw', type=click.Path(dir_okay=False, file_okay=True, exists=True), help='15.7 IPSW')
@click.option('--recreate-ramdisk', is_flag=True, help='Recreate ramdisk if already exists')
@click.option('--dump-blobs', is_flag=True, default=False, help='Dump blobs')
@click.option('--install-pogo', is_flag=True, default=False, help='Install Pogo')
@click.option('--enable-development-options', is_flag=True, default=False,
              help='Write nvram development features')
@click.option('--auto-boot', is_flag=True, default=False, help='NVRAM auto-boot value')
@click.option('--reboot', is_flag=True, default=False, help='Reboot on connection close')
def ramdisk(version: str, ramdisk_ipsw: str, recreate_ramdisk: bool, dump_blobs: bool, install_pogo: bool,
            enable_development_options: bool, auto_boot: bool, reboot: bool):
    """ Boot into ramdisk """
    exploit = Pylera1n(product_version=version, ramdisk_ipsw=ramdisk_ipsw)
    exploit.boot_ramdisk(recreate_ramdisk=recreate_ramdisk)
    exploit.perform_ramdisk_ssh_operations(
        dump_blobs=dump_blobs, install_pogo=install_pogo,
        enable_development_options=enable_development_options,
        auto_boot=auto_boot, reboot=reboot)


@cli.command(cls=Command)
@click.option('-v', '--version', help='iOS version. Can be queried automatically when device is in Normal mode')
@click.option('--ramdisk-ipsw', type=click.Path(dir_okay=False, file_okay=True, exists=True), help='15.7 IPSW')
@click.option('--ipsw', type=click.Path(dir_okay=False, file_okay=True, exists=True), help='Device correct IPSW')
@click.option('--devel', is_flag=True, help='Try using development build instead of original')
@click.option('--recreate-ramdisk', is_flag=True, help='Recreate ramdisk if already exists')
@click.option('--recreate-boot', is_flag=True, help='Recreate boot if already exists')
@click.option('--kernel-patches', type=click.Path(dir_okay=False, file_okay=True, exists=True),
              help='Use costume patch file')
@click.option('--iboot-patches', type=click.Path(dir_okay=False, file_okay=True, exists=True),
              help='Use costume patch file')
@click.option('--install-pogo', default=False, is_flag=True, help='Install Pogo')
def jailbreak(version: str, ramdisk_ipsw: str, ipsw: str, devel: bool, recreate_ramdisk: bool,
              recreate_boot: bool, kernel_patches: str, iboot_patches: str, install_pogo: bool):
    """ Perform full jailbreak """
    if kernel_patches is not None:
        kernel_patches = Path(kernel_patches)

    if iboot_patches is not None:
        iboot_patches = Path(iboot_patches)

    Pylera1n(product_version=version, ramdisk_ipsw=ramdisk_ipsw, ipsw=ipsw, devel=devel).jailbreak(
        recreate_ramdisk=recreate_ramdisk, recreate_boot=recreate_boot, kernel_patches=kernel_patches,
        iboot_patches=iboot_patches, install_pogo=install_pogo)


if __name__ == '__main__':
    try:
        cli()
    except MissingProductVersionError:
        logger.error('ProductVersion could not be queried automatically. Please specify one explicitly using "-v"')
    except IRecvNoDeviceConnectedError:
        logger.error('Failed to connect to device')
