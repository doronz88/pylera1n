# pylera1n

## Description

pyLera1n (pronounced as py-le-rain) is a python adaptation of [palera1n](https://github.com/palera1n/palera1n) - Meaning
for a list of supported devices please refer to the original authors. This project aims to make the jailbreak much more
accessible and maintainable, and with new cool features:

- Builtin [rpcserver](https://github.com/doronz88/rpc-project)
- Support modifying `/private` without performing a full jailbreak
- Support offline execution
- Provide indicative errors

Currently, the project still uses several binaries from the original repo, but eventually they will all be converted to
pure python using:

- [pymobiledevie3](https://github.com/doronz88/pymobiledevice3)
- [pyimg4](https://github.com/m1stadev/PyIMG4)
- [keystone-engine](https://www.keystone-engine.org/)

## Installation

```shell
git clone git@github.com:doronz88/pylera1n.git
cd pylera1n
git submodule update --init --recursive
python3 -m pip install -e .
```

## Usage

```
Usage: python -m pylera1n [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  jailbreak      perform full jailbreak
  put-file       put file over ssh
  ramdisk        boot into ramdisk
  ramdisk-stage  create blobs, install pogo and patch nvram if on...
  ssh            connect via ssh
```

### Full jailbreak

```shell
python3 -m pylera1n jailbreak
```

### Modifying `/private`

```shell
# boot into ramdisk, IPSW can also be downloaded automatically from internet
python3 -m pylera1n ramdisk --ipsw '~/Downloads/iPhone10,3,iPhone10,6_14.8_18H17_Restore.ipsw'

# connect to ssh
python3 -m pylera1n ssh

# mount /private
/usr/bin/mount_filesystems

# now you can access /private from /mnt2
ls /mnt2
```
