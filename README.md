# pylera1n

## Description

pyLera1n (pronounced as py-le-rain) is a python adaptation of [palera1n](https://github.com/palera1n/palera1n) - Meaning
for a list of supported devices please refer to the original authors. This project aims to make the jailbreak much more
accessible and maintainable.

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
  jailbreak  Perform full jailbreak
  put-file   Put file over ssh
  ramdisk    Boot into ramdisk
  ssh        Connect via ssh
```

### Full jailbreak

- Execute from shell:
    ```shell
    python3 -m pylera1n jailbreak
    ```
- Open `Tips` application.
- Click the `Install` button
- Click the `Tools` button
- Execute the Launch Daemons to start [`rpcserver`](https://github.com/doronz88/rpc-project)

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

## Research Notes

On iPhone X use the following disk map:

- `disk0s1s1` - `/`
- `disk0s1s2` - `/private` (SEP Protected)
- `disk0s1s7` - `/private/var/preboot`
