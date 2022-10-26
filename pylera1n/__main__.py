import logging
import os
from pathlib import Path

import click
import coloredlogs
from paramiko.config import SSH_PORT
from pymobiledevice3 import usbmux

import pylera1n
from pylera1n.palera1n.sshclient import SSHClient
from pylera1n.pylera1n import Pylera1n

coloredlogs.install(level=logging.DEBUG)

logger = logging.getLogger(__name__)

PALERA1N_PATH = Path(pylera1n.__file__).parent / 'palera1n'
BOOT_LOGO_PATH = PALERA1N_PATH / 'other' / 'bootlogo.im4p'
BINARIES_PATH = PALERA1N_PATH / 'binaries' / os.uname().sysname


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


@cli.group('stages')
@click.option('-v', '--version', help='iOS version. Can be queried automatically when device is in Normal mode')
@click.option('--palera1n', type=click.Path(dir_okay=True, file_okay=False, exists=True), default=PALERA1N_PATH,
              help='Path to paler1n repo')
@click.option('--ipsw', type=click.Path(dir_okay=False, file_okay=True, exists=True), help='14.8 IPSW')
@click.option('--rootless', is_flag=True, help='Patch Tips.app')
@click.pass_context
def stages_cli(ctx, version: str, palera1n: str, ipsw: str, rootless: bool):
    ctx.obj = Pylera1n(Path(palera1n), product_version=version, ipsw_path=ipsw, rootless=rootless)
    logger.info(ctx.obj)


@stages_cli.command()
@click.pass_context
def ramdisk(ctx):
    """ boot into 14.8 ramdisk """
    ctx.obj.boot_ramdisk()


@stages_cli.command()
@click.pass_context
def dump_blobs(ctx):
    """ boot into 14.8 ramdisk """
    ctx.obj.dump_blobs()


@stages_cli.command()
@click.pass_context
def full(ctx):
    """ boot into 14.8 ramdisk """
    ctx.obj.exploit()


if __name__ == '__main__':
    cli()
