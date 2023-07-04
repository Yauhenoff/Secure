import hashlib
import ecdsa
import sys
import argparse


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--f', default='secrets/secret.txt')
    parser.add_argument('-s', '--s', default='secrets/secret.sign')
    parser.add_argument('-k', '--k', default='secrets/public_key.pem')
    return parser

if __name__ == '__main__':

    params = create_parser().parse_args(sys.argv[1:])

    with open(params.f, 'rb') as file:
        data = file.read()
    with open(params.s, "rb") as file:
        signature = file.read()
    with open(params.k, 'r') as file:
        encoding_key = file.read()

    public_key = ecdsa.VerifyingKey.from_pem(encoding_key, hashfunc=hashlib.sha256)
    assert public_key.verify(signature, data, hashlib.sha256, sigdecode=ecdsa.util.sigdecode_der), "INVALID"
    print("VALID")
