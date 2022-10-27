import logging
from pathlib import Path

import click
import coloredlogs
from paramiko.config import SSH_PORT
from pymobiledevice3 import usbmux

import pylera1n
from pylera1n.pylera1n import Pylera1n
from pylera1n.sshclient import SSHClient

coloredlogs.install(level=logging.DEBUG)

logger = logging.getLogger(__name__)

PALERA1N_PATH = Path(pylera1n.__file__).parent / 'palera1n'


@click.group()
def cli():
    pass


@cli.command()
def ssh():
    """ connect via ssh """
    device = usbmux.select_device()
    assert device

    with SSHClient(device.connect(SSH_PORT)) as ssh:
        ssh.interact()


@cli.command()
@click.option('-v', '--version', help='iOS version. Can be queried automatically when device is in Normal mode')
@click.option('--palera1n', type=click.Path(dir_okay=True, file_okay=False, exists=True), default=PALERA1N_PATH,
              help='Path to paler1n repo')
@click.option('--ipsw', type=click.Path(dir_okay=False, file_okay=True, exists=True), help='14.8 IPSW')
@click.option('--rootless', is_flag=True, help='Patch Tips.app')
def ramdisk(version: str, palera1n: str, ipsw: str, rootless: bool):
    """ boot into ramdisk """
    exploit = Pylera1n(Path(palera1n), product_version=version, ramdisk_ipsw=ipsw, rootless=rootless)
    logger.info(exploit)
    exploit.boot_ramdisk()


@cli.command()
@click.option('-v', '--version', help='iOS version. Can be queried automatically when device is in Normal mode')
@click.option('--palera1n', type=click.Path(dir_okay=True, file_okay=False, exists=True), default=PALERA1N_PATH,
              help='Path to paler1n repo')
@click.option('--ipsw', type=click.Path(dir_okay=False, file_okay=True, exists=True), help='14.8 IPSW')
@click.option('--rootless', is_flag=True, help='Patch Tips.app')
def ramdisk_stage(version: str, palera1n: str, ipsw: str, rootless: bool):
    """ create blobs, install pogo and patch nvram if on non-rootless """
    exploit = Pylera1n(Path(palera1n), product_version=version, ramdisk_ipsw=ipsw, rootless=rootless)
    logger.info(exploit)
    exploit.ramdisk_stage()


@cli.command()
@click.option('-v', '--version', help='iOS version. Can be queried automatically when device is in Normal mode')
@click.option('--palera1n', type=click.Path(dir_okay=True, file_okay=False, exists=True), default=PALERA1N_PATH,
              help='Path to paler1n repo')
@click.option('--ipsw', type=click.Path(dir_okay=False, file_okay=True, exists=True), help='14.8 IPSW')
@click.option('--rootless', is_flag=True, help='Patch Tips.app')
def jailbreak(version: str, palera1n: str, ipsw: str, rootless: bool):
    """ perform full jailbreak (not yet supported) """
    exploit = Pylera1n(Path(palera1n), product_version=version, ramdisk_ipsw=ipsw, rootless=rootless)
    exploit.jailbreak()


if __name__ == '__main__':
    cli()
