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


@click.command()
@click.argument('product_version')
@click.option('--palera1n', type=click.Path(dir_okay=True, file_okay=False, exists=True), default=PALERA1N_PATH)
@click.option('--ipsw', type=click.Path(dir_okay=False, file_okay=True, exists=True))
@click.option('--rootless', is_flag=True)
@click.option('--tips', type=click.Path(dir_okay=False, file_okay=True, exists=True))
def cli(product_version: str, palera1n: str, ipsw: str, rootless: bool, tips: str):
    palera1n = Path(palera1n)
    gaster_path = palera1n / 'gaster'
    if not gaster_path.exists():
        download_gaster(gaster_path)

    if tips is None:
        tips = palera1n / 'pogo'
        if not tips.exists():
            download_pogo(tips)

    pylera1n = Pylera1n(palera1n, product_version=product_version, ipsw_path=ipsw, rootless=rootless, tips_app=tips)
    logger.info(pylera1n)
    try:
        pylera1n.exploit()
    except Exception:
        traceback.print_exc()


if __name__ == '__main__':
    cli()
