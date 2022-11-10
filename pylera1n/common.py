import inspect
import os
import time
from functools import wraps
from pathlib import Path

from plumbum import local
from tqdm import trange

DEFAULT_STORAGE = Path('~/.pylera1n').expanduser()
PALERA1N_PATH = Path(__file__).parent / 'palera1n'
BOOTLOGO_PATH = Path(__file__).parent / 'bootlogo.im4p'

DEVICE_PREBOOT = {
    'iPhone9,4': '/dev/disk0s1s6',
    'iPhone10,3': '/dev/disk0s1s7',
    'iPhone10,5': '/dev/disk0s1s6',
    'iPhone10,6': '/dev/disk0s1s6',
}

OS_VARIANT = os.uname().sysname

blacktop_ipsw = local['ipsw']


def wait(seconds: int) -> None:
    for _ in trange(seconds):
        time.sleep(1)


def path_to_str(*params):
    """
    Decorator for converting parameters to string.
    :param params: List of parameters names to convert.
    """

    def decorate_func(f):
        @wraps(f)
        def new_f(*args, **kwargs):
            try:
                ba = inspect.signature(f).bind(*args, **kwargs)
            except TypeError:
                # Binding failed, let the original function traceback rise.
                pass
            else:
                for param in params:
                    ba.arguments[param] = str(ba.arguments[param])
                return f(*ba.args, **ba.kwargs)
            return f(*args, **kwargs)

        signature = inspect.signature(f)
        new_params = {k: v for k, v in signature.parameters.items()}
        for p in params:
            new_params[p] = signature.parameters[p].replace(annotation=os.PathLike)
        new_f.__signature__ = signature.replace(parameters=list(new_params.values()))

        return new_f

    return decorate_func
