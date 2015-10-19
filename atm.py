#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from __future__ import print_function
import json
import os
import sys

from utils.validation import *
from utils.errors import *
from utils.network import *

ROOT_DIR = os.getcwd() + '/'

EXIT_CODE = {
    "ERROR": 255,
    "NETWORKING": 63,
    "OK": 0
}


def main():
    parser = ArgumentParser(add_help=False)
    parser.add_argument('-a', dest='account', type=val_acct_name, action='append', required=True, default=[None],
            help='The customer account name.')
    parser.add_argument('-s', dest='auth_file', type=val_file_name, action='append', default=['bank.auth'],
            help='The authentication file that bank creates for the atm.')
    parser.add_argument('-i', dest='ipaddress', type=val_ip, action='append', default=['127.0.0.1'],
            help='The IP address that bank is running on.')
    parser.add_argument('-p', dest='port', type=val_port, action='append', default=[3000],
            help='The TCP port that bank is listening on.')
    parser.add_argument('-c', dest='cardfile', type=val_file_name, action='append', default=[None],
            help='The customer atm card file.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-n', dest='create', type=initial_value, action='append', default=[None],
            help='Create a new account with the given balance.')
    group.add_argument('-d', dest='deposit', type=val_dollar_string, action='append', default=[None],
            help='Deposit the amount of money specified.')
    group.add_argument('-w', dest='withdraw', type=val_dollar_string, action='append', default=[None],
            help='Withdraw the amount of money specified.')
    group.add_argument('-g', dest='balance', action="store_true",
            help='Get the current balance of the account.')
    args, unknown = parser.parse_known_args()

    if unknown:
        return EXIT_CODE["ERROR"]

    ng = 0
    for v in sys.argv:
        if v.startswith("-"):
            for c in v[1:]:
                if c != 'g':
                    break
                ng += 1
    if ng > 1:
        return EXIT_CODE["ERROR"]

    # Make sure only 1 specified
    for k,v in vars(args).iteritems():
        if k == "balance":
            continue
        if v and len(v) > 2:
            return EXIT_CODE["ERROR"]

    # Use given value
    account = args.account[-1]
    auth_file = args.auth_file[-1]
    ipaddress = args.ipaddress[-1]
    port = args.port[-1]

    card_file = args.cardfile[-1] if args.cardfile[-1] else '{0}.card'.format(account)
    create = args.create[-1]
    deposit = args.deposit[-1]
    withdraw = args.withdraw[-1]
    balance = args.balance

    # verify the file doesn't exist if create is called
    # or exists when it is not create
    if bool(create) == os.path.isfile(card_file):
        return EXIT_CODE["ERROR"]

    # Create packet
    cmd = {'account' : account}
    res = {'account' : account}
    if create:
        cmd['amount'] = create
        cmd['create'] = ''
        res['initial_balance'] = round(float(create), 2)
    else:
        with open(card_file, 'r') as card:
            cmd['card-file'] = card.read()

        if deposit:
            cmd['amount'] = deposit
            cmd['deposit'] = ''
            res['deposit'] = round(float(deposit), 2)
        elif withdraw:
            cmd['amount'] = withdraw
            cmd['withdraw'] = ''
            res['withdraw'] = round(float(withdraw), 2)
        elif balance:
            cmd['balance'] = ''

    # open connection, send packet, wait for answer
    sock = None
    try:
        # need to send absolute path to SecureSocket
        path = ROOT_DIR + auth_file
        sock = AtmSecureSocket(ipaddress, int(port), path)
        sock.send(cmd)

        response = sock.recv()
        # verify the command was successful
        if not 'status' in response or response['status'] != 'success':
            sock.close()
            return EXIT_CODE["ERROR"]

        if not 'response' in response or not 'commit' in response:
            sock.close()
            return EXIT_CODE["ERROR"]

        # commit protocol
        sock.commit(response['commit'])
        sock.close()
    except (socket.error, ProtocolErrorException) as e:
        # print(str(e), file=sys.stderr)
        if sock:
            sock.close()
        return EXIT_CODE["NETWORKING"]
    except Exception as e:
        if sock:
            sock.close()
        # print(e, file=sys.stderr)
        return EXIT_CODE["ERROR"]

    # take necessary actions
    if create:
        # write card to file
        path = ROOT_DIR + card_file
        with open(path, 'wb') as card:
            card.write(response['response'])
    elif balance:
        res['balance'] = response['response']

    # print result
    print(json.dumps(res))
    sys.stdout.flush()

    return EXIT_CODE["OK"]


if __name__ == '__main__':
    sys.exit(main())
