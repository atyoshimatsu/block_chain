#coding:utf-8
import hashlib
from cryptography import exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime as dt

class Key():
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent = 65537,
            key_size = 2048,
            backend = default_backend()
            )
        self.public_key = self.private_key.public_key()

class Block():
    def __init__(self, private_key, index, timestamp, transaction, last_block_hash):
        self.index = index
        self.timestamp = timestamp
        self.transaction = transaction
        self.signature = private_key.sign(transaction, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                                      hashes.SHA256())
        self.last_block_hash = last_block_hash
        self.hash = self.make_self_hash()

    def make_self_hash(self):
        hash = hashlib.sha256()
        hash.update('{}-{}-{}-{}-{}'.format(self.index, self.timestamp, self.transaction, self.signature, self.last_block_hash).encode('utf-8'))
        return hash.hexdigest()

def next_block(key, last_block):
    index = last_block.index + 1
    timestamp = dt.now()
    transaction = b'A private key can be used to sign a message.'
    last_block_hash = last_block.hash
    return Block(key.private_key, index, timestamp, transaction, last_block_hash)

block_chain = []
key = Key()
firstBlock = Block(key.private_key, 0, dt.now(), b'genesis block', '')
last_block = firstBlock
for i in range(10):
    new_block = next_block(key, last_block)
    block_chain.append(new_block)
    last_block = new_block
    print(new_block.index, new_block.timestamp, new_block.transaction, new_block.last_block_hash)
    try:
        key.public_key.verify(
            new_block.signature,
            new_block.transaction,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
            hashes.SHA256()
            )
        print(new_block.index, 'Integrity of the transaction is confirmed!', new_block.transaction)
    except exceptions.InvalidSignature:
        print(new_block.index, 'Invalid Signature! The message might be falsified...', new_block.transaction)
        break

#block_chain[5].transaction = b'A private key can be used to delete a message.'

while True:
    for i in range(9):
        if block_chain[i].make_self_hash() == block_chain[i+1].last_block_hash:
           print(block_chain[i].index, 'Integrity of the transaction is confirmed!', block_chain[i].transaction)
        else:
           print(block_chain[i].index, 'Invalid hash! The message might be falsified...', block_chain[i].transaction)
           break
    break