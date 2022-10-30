# pylera1n

## Description

Python adaptation for [palera1n](https://github.com/palera1n/palera1n). **This project is very much a WIP.**
Currently allows to boot into ramdisk and connect to SSH on all checkm8-supported devices.

## Installation

```shell
git clone git@github.com:doronz88/pylera1n.git
git submodule update --init --recursive
cd pylera1n
python3 -m pip install -e pylera1n
```

## Usage

```
Usage: python -m pylera1n [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  jailbreak      perform full jailbreak
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
