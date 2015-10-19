#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from __future__ import print_function

import signal
import argparse
import json
import os
import sys
from time import sleep

from utils.validation import *
from utils.errors import *
from utils.network import *

from Crypto.Random.random import StrongRandom
from threading import Lock

import traceback

EXIT_CODE = {
    "ERROR": 255,
    "OK": 0
}

PROTOCOL_ERROR = 'protocol_error'
KEY_SIZE = 2048

MIN_COMMIT = 5
MAX_COMMIT = 10000

class BankTCPHandler(SocketServer.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def setup(self):
        self.server.ref()
        self.account = None
        self.secureRequest = None
        try:
            self.secureRequest = BankSecureSocket(self.request, self.server.key_serv, self.server.key_atm)
        except (socket.error, ProtocolErrorException) as e:
            # print("Error: " + str(e), file=sys.stderr)
            print(PROTOCOL_ERROR)
            sys.stdout.flush()
            return

    def handle(self):
        # self.request is the TCP socket connected to the client
        if not self.secureRequest:
            return

        try:
            cmd = self.secureRequest.recv()
            if not 'account' in cmd:
                raise InvalidArgumentException('I need to know which account I dealing with, ATM grow up a little bit...')

            account_name = val_acct_name(cmd['account'])

            # Validate cmd entries
            if 'amount' in cmd:
                money = Money.new(cmd['amount'])

            if 'create' in cmd:
                #is this ACTUALLY a new account?
                if not self.server.check_and_reserve(account_name):
                    raise OperationFailed('account already exists')
                if money < Money(10, 0):
                    raise InvalidArgumentException("Ohoh, someone mess up with the packet and we did not see it coming... :'(")

                salt, hashpass, card_file = self.server.create_card(account_name)
                response = card_file
            else:
                #Authenticate the cmd
                if not 'card-file' in cmd or not self.server.authenticate_user(account_name, cmd['card-file']):
                    raise OperationFailed('failed to authenticate account')

                self.account = self.server.accounts[account_name]
                self.account.lock()

                if not 'balance' in cmd and money <= Money(0, 0):
                    raise InvalidArgumentException("Really ATM, you send me negative money??????")

                response = ""
                if 'withdraw' in cmd:
                    if not self.account.check_withdraw(money):
                        raise OperationFailed('invalid withdraw')
                elif 'deposit' in cmd:
                    # no more test for deposit
                    pass
                elif 'balance' in cmd:
                    balance = self.account.balance()
                    response = round(float(str(balance)), 2)
                else:
                    raise InvalidArgumentException("I am sick of your little games ATM, I don't know what to do...")

            commit_msg = StrongRandom().randint(MIN_COMMIT, MAX_COMMIT)
            self.secureRequest.send({ "status": "success", "response": response, "commit": commit_msg})

            # commit protocol
            self.secureRequest.commit(commit_msg);

            # commit
            res = {"account" : account_name}
            if 'withdraw' in cmd:
                self.account.withdraw(money)
                res['withdraw'] = round(float(cmd['amount']), 2)
            elif 'deposit' in cmd:
                self.account.deposit(money)
                res['deposit'] = round(float(cmd['amount']), 2)
            elif 'create' in cmd:
                self.server.add_account(account_name, money, salt, hashpass)
                res['initial_balance'] = round(float(cmd['amount']), 2)
            elif 'balance' in cmd:
                res['balance'] = round(float(str(balance)), 2)

            print(json.dumps(res))
            sys.stdout.flush()

        except (socket.error, ProtocolErrorException) as e:
            # print("Error: " + str(e), file=sys.stderr)
            print(PROTOCOL_ERROR)
            sys.stdout.flush()
        except InvalidArgumentException as e:
            # Should never happen
            # print("Error: " + str(e), file=sys.stderr)
            self.secureRequest.send({"status": "failed", "error": "Do your job, stop sending invalid arguments... Dammit ATM!!!"})
        except Exception as e:
            # print("Error: " + str(e), file=sys.stderr)
            try:
                self.secureRequest.send({"status": "failed", "error": str(e)})
            except Exception as e:
                pass
                # print("Error Sending Error Response: " + str(e), file=sys.stderr)

    def finish(self):
        # print("Clean up time", file=sys.stderr)
        if self.secureRequest:
            self.secureRequest.close()
        if self.account:
            self.account.unlock()
        self.server.unref()


class BankNetwork(SocketServer.ThreadingMixIn, SocketServer.TCPServer):

    allow_reuse_address = True

    def __init__(self, host, port, authfile):
        SocketServer.TCPServer.__init__(self, (host, port), BankTCPHandler) # error handling?

        self.key = self.create_auth_file(authfile)
        self.accounts = {}
        self.pending_accounts = []
        self.lock = Lock()

        self.__shutdown_request = False
        self.__ref = 0

    def serve_forever(self, poll_interval=0.5):
        while not self.__shutdown_request:
            self.handle_request()

    def check_and_reserve(self, name):
        self.lock.acquire()
        if name in self.pending_accounts or name in self.accounts:
            self.lock.release()
            return False

        # reserve the name
        self.pending_accounts.append(name)
        self.lock.release()
        return True

    def add_account(self, name, amt, salt, hashpass):
        self.lock.acquire()
        self.pending_accounts.remove(name)
        self.accounts[name] = Account(name, amt, salt, hashpass)
        self.lock.release()

    def ref(self):
        self.lock.acquire()
        self.__ref += 1
        self.lock.release()

    def unref(self):
        self.lock.acquire()
        self.__ref -= 1
        self.lock.release()

    def create_auth_file(self, path):

        if os.path.isfile(path):
            raise AuthfileExistsException()

        # Create two private key
        self.key_serv = RSA.generate(KEY_SIZE)
        self.key_atm = RSA.generate(KEY_SIZE)

        # save ATM private key and server public key in file
        with open(path,'w') as f:
            f.write(self.key_serv.publickey().exportKey('PEM'))
            f.write("#####")
            f.write(self.key_atm.exportKey('PEM'))
            # REQUIEREMENT
            print("created")
            sys.stdout.flush()

    def create_card(self, ident):

        salt = os.urandom(16)
        password = os.urandom(16)

        sha = SHA512.new()
        sha.update(salt)
        sha.update(password)
        sha.update(ident)

        return salt, sha.digest(), password

    def authenticate_user(self, ident, card):
        if not ident in self.accounts:
            return False
        return self.accounts[ident].authenticate(card, self.key_serv)

    def server_close(self):
        # print("Shutting Down Server", file=sys.stderr)
        self.__shutdown_request = True

        while self.__ref > 0:
            sleep(0.02)

        return SocketServer.TCPServer.server_close(self)

def main():
    parser = ArgumentParser(add_help=False)
    parser.add_argument('-p', dest='port', type=val_port, action='append', default=[3000], help='The listening port number.')
    parser.add_argument('-s', dest='auth_file', type=val_file_name, action='append', default=['bank.auth'], help='The name of the auth file.')
    args, unknown = parser.parse_known_args()

    if unknown:
        return EXIT_CODE["ERROR"]

    # Make sure only 1 specified
    for v in vars(args).itervalues():
        if len(v) > 2:
            return EXIT_CODE["ERROR"]

    # Use given value
    args.port = args.port[-1]
    args.auth_file = args.auth_file[-1]

    server = None
    def signal_handler(signal, handler):
        if server:
            server.server_close()
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    # print(args, file=sys.stderr)
    try:
        server = BankNetwork("localhost", int(args.port), args.auth_file)
        server.serve_forever()
    except AuthfileExistsException as e:
        # print(str(e), file=sys.stderr)
        return EXIT_CODE['ERROR']

    return EXIT_CODE['OK']


if __name__ == '__main__':
    sys.exit(main())
