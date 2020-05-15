#!/usr/bin/env python3
"""
Netio Command line interface
"""

import argparse
import configparser

import requests
import os
import sys
from urllib.parse import urlparse, urlunparse

from .exceptions import NetioException
from . import Netio


def str2action(s: str) -> Netio.ACTION:
    """Parse Device.ACTION, either by name or by integer representation """
    try:
        return Netio.ACTION[s]
    except KeyError:
        try:
            return Netio.ACTION(int(s))
        except ValueError:
            raise argparse.ArgumentTypeError(f"{s!r} is not a valid {Netio.ACTION.__name__}")


# all Device.ACTION choices, including INT
ACTION_CHOICES = [e.value for e in Netio.ACTION] + [e.name for e in Netio.ACTION]

EPILOG = """
Report bugs to: averner@netio.eu
project repository and documentation: https://github.com/netioproducts/PyNetio
released under MIT license by NETIO Products a.s.
"""


def get_arg(arg, config, name, section, default):
    """
    argument is looked up in this order:
     1. argument itself
     2. specified section
     3. DEFAULT section
     4. param default
    """
    if arg == default:
        if section in config.sections():
            return config[section].get(name, config['DEFAULT'].get(name, default))


def load_config(args):
    """ Load configration file and other other configs """

    # TODO ENV variable

    if not args.conf:
        return args

    config = configparser.ConfigParser()
    config.read(args.conf)

    u = urlparse(args.device)

    args.cert = get_arg(args.cert, config, 'cert', u.netloc, True)
    args.user = get_arg(args.user, config, 'user', u.netloc, None)
    args.password = get_arg(args.password, config, 'password', u.netloc, None)
    args.no_cert_warning = get_arg(args.no_cert_warning, config, 'password', u.netloc, False)

    return args


def cli_app(args):
    """ Main entry point of the app """

    args = load_config(args)

    if args.no_cert_warning:
        requests.packages.urllib3.disable_warnings()

    u = urlparse(args.device)
    u = u._replace(path='/netio.json') if not u.path else u  # no path specified

    # try to run the specified command, on fail print nice fail message
    try:
        device = Netio(urlunparse(u), auth_rw=(args.user, args.password), verify=args.cert, skip_init=True)
        args.func(device, args)
    except NetioException as e:
        print(e.args[0], file=sys.stderr)


def command_set(device: Netio, args: argparse.Namespace) -> None:
    """ Set the output specified in args.id to args.action """
    device.set_output(args.id, args.action)


def command_get(device: Netio, args: argparse.Namespace) -> None:
    """ Print the state of the output and exit """

    if args.id == -1:
        outputs = device.get_outputs()
    else:
        outputs = (device.get_output(args.id),)

    print('id', 'Name', 'State', 'Action', 'Delay', 'Current', 'PowerFactor', 'Load', 'Energy', sep=args.delim)
    for o in outputs:
        print(o.ID, o.Name, o.State, o.Action, o.Delay, o.Current, o.PowerFactor, o.Load, o.Energy, sep=args.delim)


def cli_main(argv):
    parser = argparse.ArgumentParser(epilog=EPILOG)  # prog='netio')

    parser.add_argument('device', metavar='DEVICE', action='store', help='Netio device URL')

    parser.add_argument("-u", "--user", action="store", dest='user', metavar='U', help='M2M API username')
    parser.add_argument("-p", "--password", action="store", dest='password', metavar='P', help='M2M API password')

    parser.add_argument("-C", "--cert", action="store_false", dest='cert', default=True, help='HTTPS Certificate')
    parser.add_argument("-c", "--config", action="store", dest="conf", metavar='CFG', help='Configuration file')
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument(
        "--no-cert-warning",
        action="store_true",
        help="Disable warnings about certificate's subjectAltName versus commonName",
    )

    # TODO version from setup
    parser.add_argument("--version", action="version", version="%(prog)s (version {version})".format(version="0.0.1"))

    command_parser = parser.add_subparsers(metavar="COMMAND", help="netio device command", required=True)

    # GET command subparser
    get_parser = command_parser.add_parser("get", help="GET output state")
    get_parser.add_argument('id', metavar='ID', nargs='?', type=int, default=-1, help='Output ID. All if not specified')
    get_parser.set_defaults(func=command_get)
    get_parser.add_argument("-d", "--delimiter", action="store", dest="delim", default=";", help='')

    # SET command subparser
    set_parser = command_parser.add_parser("set", help="SET output state")
    set_parser.set_defaults(func=command_set)
    set_parser.add_argument('id', metavar='ID', type=int)
    set_parser.add_argument('action', metavar='ACTION', type=str2action, choices=ACTION_CHOICES)

    # INFO command subparser
    info_parser = command_parser.add_parser("info", help="show device info")
    info_parser.set_defaults(func=lambda d, x: print("info_command"))

    args = parser.parse_args()
    cli_app(args)


def main():
    cli_main(sys.argv)


if __name__ == "__main__":
    main()
