import logging
from pathlib import Path

import click
import coloredlogs
from paramiko.config import SSH_PORT
from pymobiledevice3 import usbmux

import pylera1n
from pylera1n.exceptions import MissingProductVersionError
from pylera1n.pylera1n import Pylera1n
from pylera1n.sshclient import SSHClient

coloredlogs.install(level=logging.INFO)

logger = logging.getLogger(__name__)
logging.getLogger('paramiko.transport').disabled = True

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
    """ connect via ssh """
    device = usbmux.select_device()
    assert device

    with SSHClient(device.connect(SSH_PORT)) as ssh:
        ssh.interact()


@cli.command(cls=Command)
@click.argument('source', type=click.Path(file_okay=True, dir_okay=False, exists=True))
@click.argument('destination')
def put_file(source, destination):
    """ put file over ssh """
    device = usbmux.select_device()
    assert device

    with SSHClient(device.connect(SSH_PORT)) as ssh:
        ssh.put_file(source, destination)


@cli.command(cls=Command)
@click.option('-v', '--version', help='iOS version. Can be queried automatically when device is in Normal mode')
@click.option('--palera1n', type=click.Path(dir_okay=True, file_okay=False, exists=True), default=PALERA1N_PATH,
              help='Path to paler1n repo')
@click.option('--ramdisk-ipsw', type=click.Path(dir_okay=False, file_okay=True, exists=True), help='14.8 IPSW')
@click.option('--recreate-ramdisk', is_flag=True, help='Recreate ramdisk if already exists')
def ramdisk(version: str, palera1n: str, ramdisk_ipsw: str, recreate_ramdisk: bool):
    """ boot into ramdisk """
    exploit = Pylera1n(Path(palera1n), product_version=version, ramdisk_ipsw=ramdisk_ipsw)
    logger.info(exploit)
    exploit.boot_ramdisk(recreate_ramdisk=recreate_ramdisk)


@cli.command(cls=Command)
@click.option('-v', '--version', help='iOS version. Can be queried automatically when device is in Normal mode')
@click.option('--palera1n', type=click.Path(dir_okay=True, file_okay=False, exists=True), default=PALERA1N_PATH,
              help='Path to paler1n repo')
@click.option('--ramdisk-ipsw', type=click.Path(dir_okay=False, file_okay=True, exists=True), help='14.8 IPSW')
@click.option('--devel', is_flag=True, help='Try using developement build instead of original')
@click.option('--recreate-ramdisk', is_flag=True, help='Recreate ramdisk if already exists')
def ramdisk_stage(version: str, palera1n: str, ramdisk_ipsw: str, rootless: bool, recreate_ramdisk: bool):
    """ create blobs, install pogo and patch nvram if on non-rootless """
    exploit = Pylera1n(Path(palera1n), product_version=version, ramdisk_ipsw=ramdisk_ipsw, devel=rootless)
    logger.info(exploit)
    exploit.ramdisk_stage(recreate_ramdisk=recreate_ramdisk)


@cli.command(cls=Command)
@click.option('-v', '--version', help='iOS version. Can be queried automatically when device is in Normal mode')
@click.option('--palera1n', type=click.Path(dir_okay=True, file_okay=False, exists=True), default=PALERA1N_PATH,
              help='Path to paler1n repo')
@click.option('--ramdisk-ipsw', type=click.Path(dir_okay=False, file_okay=True, exists=True), help='14.8 IPSW')
@click.option('--ipsw', type=click.Path(dir_okay=False, file_okay=True, exists=True), help='Device correct IPSW')
@click.option('--devel', is_flag=True, help='Try using developement build instead of original')
@click.option('--recreate-ramdisk', is_flag=True, help='Recreate ramdisk if already exists')
def jailbreak(version: str, palera1n: str, ramdisk_ipsw: str, ipsw: str, devel: bool, recreate_ramdisk: bool):
    """ perform full jailbreak """
    exploit = Pylera1n(Path(palera1n), product_version=version, ramdisk_ipsw=ramdisk_ipsw, ipsw=ipsw, devel=devel)
    exploit.jailbreak(recreate_ramdisk=recreate_ramdisk)


if __name__ == '__main__':
    try:
        cli()
    except MissingProductVersionError:
        logger.error('ProductVersion could not be queried automatically. Please specify one explicitly using "-v"')
