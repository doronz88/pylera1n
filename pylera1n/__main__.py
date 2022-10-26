import logging
import os
import traceback
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import click
import coloredlogs
import requests

import pylera1n
from pylera1n.pylera1n import Pylera1n

coloredlogs.install(level=logging.DEBUG)

logger = logging.getLogger(__name__)

PALERA1N_PATH = Path(pylera1n.__file__).parent / 'palera1n'
BOOT_LOGO_PATH = PALERA1N_PATH / 'other' / 'bootlogo.im4p'
BINARIES_PATH = PALERA1N_PATH / 'binaries' / os.uname().sysname


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


@click.group()
def cli():
    pass


@cli.command()
@click.argument('product_version')
@click.option('--palera1n', type=click.Path(dir_okay=True, file_okay=False, exists=True), default=PALERA1N_PATH,
              help='Path to paler1n repo')
@click.option('--ipsw', type=click.Path(dir_okay=False, file_okay=True, exists=True), help='14.8 IPSW')
@click.option('--rootless', is_flag=True, help='Patch Tips.app')
@click.option('--pogo', type=click.Path(dir_okay=False, file_okay=True, exists=True), help='Pogo.app file')
def ramdisk(product_version: str, palera1n: str, ipsw: str, rootless: bool, pogo: str):
    """ boot into 14.8 ramdisk """
    palera1n = Path(palera1n)
    gaster_path = palera1n / 'gaster'
    if not gaster_path.exists():
        download_gaster(gaster_path)

    if pogo is None:
        pogo = palera1n / 'pogo'
        if not pogo.exists():
            download_pogo(pogo)

    pylera1n = Pylera1n(palera1n, product_version=product_version, ipsw_path=ipsw, rootless=rootless, pogo=pogo)
    logger.info(pylera1n)
    try:
        pylera1n.exploit()
    except Exception:
        traceback.print_exc()


if __name__ == '__main__':
    cli()
