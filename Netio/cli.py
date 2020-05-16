from . import Netio
from distutils.util import strtobool
from pathlib import Path
from urllib.parse import urljoin
import argparse
import configparser
import getpass
import itertools
import os
import requests
import sys


def add_output_actions_for_arg(actions, arg, action):
    if arg:
        for item in flatten(arg):
            actions[item] = action


def bool_or_str(string):
    try:
        return bool(strtobool(string.lower()))
    except ValueError:
        return string


def create_argument_parser():
    default_config = os.getenv('NETIO_CONFIG', 'netio.ini')

    parser = argparse.ArgumentParser(description='NETIO command line tool',
        epilog= 'You may specify the default configuration file in the '
            'environment variable NETIO_CONFIG.')
    parser.add_argument('-c', '--config', type=Path, default=default_config,
        help='configuration file (default is {})'.format(default_config))

    parser.add_argument('-d', '--device', default=None,
        help='the NETIO device to interact with')
    parser.add_argument('-u', '--user', default=None,
        help='user name for accessing device')
    parser.add_argument('-p', '--password-prompt', action='store_true',
        help='prompt for password')
    parser.add_argument('--verify', default=None,
        help='your root of trust for certificate verification, this could be a self-signed certificate')
    parser.add_argument('--no-urllib-warnings', action='store_true', default=None,
        help='disable warnings about certificate properties')

    parser.add_argument('--verbose', action='store_true',
        help='be verbose (e.g. print column headers)')
    subparsers = parser.add_subparsers(metavar='COMMAND', help='sub commands')

    get_parser = subparsers.add_parser('get', help='get outputs')
    get_parser.set_defaults(function=get_command)
    get_parser.add_argument('outputs', metavar='OUTPUTS', type=int,
        action='append', nargs='*',
        help='outputs to get status for')

    set_parser = subparsers.add_parser('set', help='set outputs')
    set_parser.set_defaults(function=set_command)
    set_parser.add_argument('--off', metavar='OUTPUT', type=int,
        action='append', nargs='+',
        help='outputs to turn off')
    set_parser.add_argument('--on', metavar='OUTPUT', type=int,
        action='append', nargs='+',
        help='outputs to turn on')
    set_parser.add_argument('--short-off', metavar='OUTPUT', type=int,
        action='append', nargs='+',
        help='outputs to turn off for a short period')
    set_parser.add_argument('--short-on', metavar='OUTPUT', type=int,
        action='append', nargs='+',
        help='outputs to turn on for a short period')
    set_parser.add_argument('--toggle', metavar='OUTPUT', type=int,
        action='append', nargs='+',
        help='outputs to toggle')

    return parser


def create_output_actions(args):
    actions = {}

    add_output_actions_for_arg(actions, args.off, Netio.ACTION.OFF)
    add_output_actions_for_arg(actions, args.on, Netio.ACTION.ON)
    add_output_actions_for_arg(actions, args.short_off, Netio.ACTION.SHORT_OFF)
    add_output_actions_for_arg(actions, args.short_on, Netio.ACTION.SHORT_ON)
    add_output_actions_for_arg(actions, args.toggle, Netio.ACTION.TOGGLE)

    return actions


def flatten(iterable):
    return itertools.chain.from_iterable(iterable)


def merge_config_into_args(args, config):
    # Select the config file section to take the values from. Configparser
    # automagically merges values from 'DEFAULT into the selected section if it
    # is not present there.
    section_name = args.device if args.device in config.sections() else 'DEFAULT'
    section = config[section_name]

    # Update values not specified via command line arguments.
    if args.device == None:
        args.device = section.get('device', None)
    if args.user == None:
        args.user = section.get('user', None)
    if args.verify == None:
        args.verify = section.get('verify', None)
    if args.no_urllib_warnings == None:
        args.no_urllib_warnings = section.get('no_urllib_warnings', None)

    # Store password in an additional argument variable.
    args.password = section.get('password', None)


def program_name():
    return os.path.basename(sys.argv[0])


def resolve_config_path(config, path):
    config = Path(config)
    path = Path(path)
    result = path

    if not path.is_absolute():
        result = config.parent / path

    return result





def get_command(device, args):
    """
    Prints output state information for the requested outputs in a tabular form
    suitable for further processing in a pipe (grep, awk, ...).
    """
    requested_ids = set(flatten(args.outputs))
    all_outputs = device.get_outputs()

    if len(requested_ids) > 0:
        requested_outputs = [o for o in all_outputs if o.ID in requested_ids]
    else:
        requested_outputs = all_outputs

    line_format = '{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}'

    if args.verbose:
        print(line_format.format('id', 'name', 'state', 'action', 'delay',
            'current', 'pf', 'load', 'energy'))

    for output in requested_outputs:
        print(line_format.format(output.ID, output.Name, output.State,
            output.Action, output.Delay, output.Current, output.PowerFactor,
            output.Load, output.Energy))


def set_command(device, args):
    actions = create_output_actions(args)

    # All action arguments are optional at the time of argument parsing. So we
    # could end up with an empty action list which gets sorted out here because
    # setting outputs fails at parsing the response in this situation.
    if len(actions) == 0:
        print('{}: at least one output required.'.format(program_name()),
            file=sys.stderr)
        sys.exit(1)

    device.set_outputs(actions)




def main():
    netio_cli(sys.argv)


def netio_cli(argv):
    parser = create_argument_parser()
    args = parser.parse_args(argv[1:])

    config = configparser.ConfigParser()
    config.read(args.config)

    verify_from_args = args.verify != None
    merge_config_into_args(args, config)

    # The 'verify' argument for configuring certificate verification is
    # versatile. It may be either a bool or a string with the following
    # meanings:
    #
    #     True: use default root of trust
    #
    #     False: disable certificate verification (you have been warned: here
    #     be dragons!)
    #
    #     a string: file or diretory name for a custom root of trust
    #
    # So handling this parameter requires some extra care.
    args.verify = bool_or_str(args.verify)
    if not verify_from_args and type(args.verify) == str:
        args.verify = resolve_config_path(args.config, args.verify)

    if args.no_urllib_warnings:
        # Disable urllib's warnings to get rid of warnings about certificate's
        # subjectAltName versus commonName.
        requests.packages.urllib3.disable_warnings()

    if args.password_prompt:
        # Prompt for passwor upon request only for not blocking in scripting.
        args.password = getpass.getpass(prompt='password: ')


    # FIXME: Check for missing arguments not covered by ArgumentParser's checks
    # due to config file merging.


    url = urljoin(args.device, 'netio.json')
    auth = (args.user, args.password)
    device = Netio(url, auth_rw=auth, verify=args.verify)

    if hasattr(args, 'function'):
        args.function(device, args)
    else:
        parser.print_usage(file=sys.stderr)


if __name__ == '__main__':
    main()
