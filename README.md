# pylera1n

## Description

Python adaptation for [pelara1n](https://github.com/palera1n/palera1n).

## Installation

```shell
git clone git@github.com:doronz88/pylera1n.git
git submodule update --init --recursive
cd pylera1n
python3 -m pip install -e pylera1n
```

## Usage

```
Usage: python -m pylera1n stages [OPTIONS] COMMAND [ARGS]...

Options:
  -v, --version TEXT    iOS version. Can be queried automatically when device
                        is in Normal mode
  --palera1n DIRECTORY  Path to paler1n repo
  --ipsw FILE           14.8 IPSW
  --rootless            Patch Tips.app
  --help                Show this message and exit.

Commands:
  dump-blobs  dump blobs
  full        perform all jailbreak stages
  ramdisk     boot into 14.8 ramdisk
```

