import logging
from pathlib import Path

import IPython
import click
import coloredlogs
from pymobiledevice3.exceptions import IRecvNoDeviceConnectedError

import pylera1n
from pylera1n.exceptions import MissingProductVersionError
from pylera1n.pylera1n import Pylera1n, wait_device_ssh, KernelcachdStrategy

coloredlogs.install(level=logging.INFO)

logger = logging.getLogger(__name__)
logging.getLogger('paramiko.transport').disabled = True
logging.getLogger('pymobiledevice3.irecv').disabled = True
logging.getLogger('urllib3.connectionpool').disabled = True
logging.getLogger('paramiko.transport.sftp').disabled = True
logging.getLogger('blib2to3.pgen2.driver').disabled = True

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
@click.option('--ipython', is_flag=True)
def ssh(ipython: bool):
    """ Connect via ssh """
    with wait_device_ssh() as ssh:
        if ipython:
            IPython.embed()
        else:
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
@click.option('--fakefs', is_flag=True, default=False, help='Install fakefs')
@click.option('--kernelcachd', type=click.Choice(['pongokpf', 'normal']))
@click.option('--auto-boot', is_flag=True, default=False, help='NVRAM auto-boot value')
@click.option('--reboot', is_flag=True, default=False, help='Reboot on connection close')
def ramdisk(version: str, ramdisk_ipsw: str, recreate_ramdisk: bool, dump_blobs: bool,
            fakefs: bool, kernelcachd: str, auto_boot: bool, reboot: bool):
    """ Boot into ramdisk """
    if kernelcachd == 'pongokpf':
        kernelcachd = KernelcachdStrategy.PongoKpf
    elif kernelcachd == 'normal':
        kernelcachd = KernelcachdStrategy.Normal
    else:
        kernelcachd = None

    exploit = Pylera1n(product_version=version, ramdisk_ipsw=ramdisk_ipsw)
    exploit.boot_ramdisk(recreate_ramdisk=recreate_ramdisk)
    exploit.perform_ramdisk_ssh_operations(
        dump_blobs=dump_blobs, fakefs=fakefs,
        kernelcachd=kernelcachd, auto_boot=auto_boot, reboot=reboot)


@cli.command(cls=Command)
@click.option('-v', '--version', help='iOS version. Can be queried automatically when device is in Normal mode')
@click.option('--ramdisk-ipsw', type=click.Path(dir_okay=False, file_okay=True, exists=True), help='15.7 IPSW')
@click.option('--ipsw', type=click.Path(dir_okay=False, file_okay=True, exists=True), help='Device correct IPSW')
@click.option('--devel', is_flag=True, help='Try using development build instead of original')
@click.option('--recreate-boot', is_flag=True, help='Recreate boot if already exists')
@click.option('--bootx', default=False, is_flag=True, help='Use bootx instead of fsboot technique')
@click.option('--boot-device', help='boot device')
def jailbreak(version: str, ramdisk_ipsw: str, ipsw: str, devel: bool, recreate_boot: bool, bootx: bool,
              boot_device: str):
    """ Perform full jailbreak """
    if not bootx:
        if boot_device is None:
            raise click.BadOptionUsage('--boot-device', 'either --bootx or --boot-device must be specified')

    Pylera1n(product_version=version, ramdisk_ipsw=ramdisk_ipsw, ipsw=ipsw, devel=devel).jailbreak(
        recreate_boot=recreate_boot, bootx=bootx, boot_device=boot_device)


if __name__ == '__main__':
    try:
        cli()
    except MissingProductVersionError:
        logger.error('ProductVersion could not be queried automatically. Please specify one explicitly using "-v"')
    except IRecvNoDeviceConnectedError:
        logger.error('Failed to connect to device')
