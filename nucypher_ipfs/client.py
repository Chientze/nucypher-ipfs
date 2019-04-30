import copy
import os
import logging
import ipfsapi
import datetime
import json
import base64
import maya
from nucypher.crypto.kits import UmbralMessageKit

from umbral.keys import UmbralPrivateKey, UmbralPublicKey

from faker import Faker

from nucypher.characters.lawful import Alice,Bob, Ursula
from nucypher.config.characters import AliceConfiguration
from nucypher.crypto.powers import DecryptingPower, SigningPower
from nucypher.network.middleware import RestMiddleware
from nucypher.utilities.logging import SimpleObserver
from nucypher.keystore.keypairs import DecryptingKeypair, SigningKeypair

from nucypher.characters.lawful import Enrico

fake = Faker()

def connect_ursula(ursula_url = "https://localhost:9151"):
    client = Client(ursula_url)
    return client


class Client(object):
    URSULA_SEEDNODE_URI = ""

    def __init__(self, ursula_url):
        self.URSULA_SEEDNODE_URI = ursula_url
        # todo : customise ipfs host
        self.ipfs = ipfsapi.connect("https://ipfs.infura.io",5001)
        random_name = fake.name()
        self.label = random_name.encode()
        self.m = 2
        self.n = 3

    def node_info(self):
        return self.ipfs.id()

    def generate_recipient_keys(self):
        enc_privkey = UmbralPrivateKey.gen_key()
        sig_privkey = UmbralPrivateKey.gen_key()

        recipient_privkeys = {
            'enc': enc_privkey.to_bytes().hex(),
            'sig': sig_privkey.to_bytes().hex(),
        }

        enc_pubkey = enc_privkey.get_pubkey()
        sig_pubkey = sig_privkey.get_pubkey()

        recipient_pubkeys = {
            'enc': enc_pubkey.to_bytes().hex(),
            'sig': sig_pubkey.to_bytes().hex()
        }

        return recipient_privkeys, recipient_pubkeys
    
    def generate_owner_policy_public_key(self, max_days):
        self.ursula = Ursula.from_seed_and_stake_info(seed_uri=self.URSULA_SEEDNODE_URI,federated_only=True,minimum_stake=0)
        policy_end_datetime = maya.now() + datetime.timedelta(days=max_days)
        
        self.ALICE = Alice(network_middleware=RestMiddleware(),
              known_nodes=[self.ursula],
              learn_on_same_thread=True,
              federated_only=True)
        
        policy_pubkey = self.ALICE.get_policy_pubkey_from_label(self.label)
        return policy_pubkey

    def uploadFile(self, filename, policy_pubkey):
        data_source = Enrico(policy_encrypting_key=policy_pubkey)
        data_source_public_key = bytes(data_source.stamp)
        file = open(filename, "r").read()
        encoded = base64.b64encode(file.encode())
        encrypt_message, _signature = data_source.encrypt_message(encoded)
        kit_bytes = encrypt_message.to_bytes()

        try:
            os.mkdir("./tmp")
        except Exception as e:
            logging.info("temp folder exist")

        temp = open('./tmp/'+filename, 'wb')
        temp.write(kit_bytes)
        temp.close()
        res = self.ipfs.add('./tmp/'+filename)
        receipt_info = {
            "data_source_public_key" : data_source_public_key.hex(),
            "hash_key" : res['Hash']
        }
        return receipt_info
        
    def authorize(self, recipient_pubkeys, max_days=5):
        
        powers_and_material = {
            DecryptingPower : UmbralPublicKey.from_bytes(bytes.fromhex(recipient_pubkeys["enc"])),
            SigningPower : UmbralPublicKey.from_bytes(bytes.fromhex(recipient_pubkeys["sig"]))
        }

        recipient = Bob.from_public_keys(powers_and_material=powers_and_material, federated_only=True)
        
        policy_end_datetime = maya.now() + datetime.timedelta(days=max_days)
        m,n = self.m, self.n
        self.ALICE.start_learning_loop(now=True)
        policy = self.ALICE.grant(recipient, self.label, m=m, n=n, expiration=policy_end_datetime)
        alices_pubkey = bytes(self.ALICE.stamp)
        policy_info = {
            "policy_pubkey" : policy.public_key.to_bytes().hex(),
            "alice_sig_pubkey" : alices_pubkey,
            "label" : self.label.decode("utf-8")
        }
        return policy_info
    
    def downloadFile(self,downloadFilename, recipient_privkeys , receipt , policy_info ):
        hash = receipt['hash_key']
        input = self.ipfs.cat(hash)

        ursula = Ursula.from_seed_and_stake_info(seed_uri=self.URSULA_SEEDNODE_URI, federated_only=True, minimum_stake=0)

        bob_enc_keypair = DecryptingKeypair(private_key=UmbralPrivateKey.from_bytes(bytes.fromhex(recipient_privkeys["enc"]))  )
        bob_sig_keypair = SigningKeypair(private_key=UmbralPrivateKey.from_bytes(bytes.fromhex(recipient_privkeys["sig"])))
        enc_power = DecryptingPower(keypair=bob_enc_keypair)
        sig_power = SigningPower(keypair=bob_sig_keypair)
        power_ups = [enc_power, sig_power]

        authorizedRecipient = Bob(
            is_me=True,
            federated_only=True,
            crypto_power_ups=power_ups,
            start_learning_now=True,
            abort_on_learning_error=True,
            known_nodes=[ursula],
            save_metadata=False,
            network_middleware=RestMiddleware(),
        )

        policy_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(policy_info["policy_pubkey"]))

        enrico_as_understood = Enrico.from_public_keys(
            {SigningPower: UmbralPublicKey.from_bytes(bytes.fromhex(receipt['data_source_public_key']))  },
            #{SigningPower: data_source_public_key},
            policy_encrypting_key=policy_pubkey
        )
        alice_pubkey_restored = UmbralPublicKey.from_bytes((policy_info['alice_sig_pubkey']))
        authorizedRecipient.join_policy(policy_info['label'].encode(), alice_pubkey_restored)


        
        kit = UmbralMessageKit.from_bytes(input)

        delivered_cleartexts = authorizedRecipient.retrieve(message_kit=kit,
                                        data_source=enrico_as_understood,
                                        alice_verifying_key=alice_pubkey_restored,
                                        label=(policy_info['label'].encode()))

        #delivered_cleartexts = authorizedRecipient.retrieve(message_kit=kit,data_source=data_source,alice_verifying_key=alice_pubkey_restored, label=(policy_info['label'].encode())  )

        data = base64.b64decode(delivered_cleartexts[0])
        output = open('./'+downloadFilename, 'wb')
        output.write(data)
        output.close()
