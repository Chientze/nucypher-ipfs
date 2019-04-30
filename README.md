# NuCypher IPFS

This Python SDK allows python developer experiment NuCypher network to securely upload and download your files to IPFS.

## Installation

install with pip:
```
pip install nucypher-ipfs 
```
If runs into connect module issue, it may cause of duplicate dependencies, fix by
```
pip uninstall ipfs-api ipfsapi
pip install ipfsapi
```

## Usage

To use this, you must first import it and specify host name and port of a runnning instance of Ursula:

```
>>> import nucypher_ipfs

>>> client = nucypher_ipfs.connect_ursula("https://localhost:9151")
```

This current version connects to public IPFS gateway of Infura through API thus no need to setup additional IPFS host.

Now that you have a client instance, you can make requests and process responses from the service. To begin we apparently need to get a public key of our recipient or we can generate a new one from following:

```
>>> recipient_privkeys, recipient_pubkeys = client.generate_recipient_keys()
```

Policy public keys will be required for the data owner to encrypt the data that belongs to the policy:
```
>>> policy_pubkey = client.generate_owner_policy_public_key(max_days=5)
```

Specify the file to be uploaded to IPFS network, the hash of our encrypted file will be returned when it finish. 

```
>>> filename = "test.txt"

>>> receipt = client.uploadFile(filename=filename , policy_pubkey=policy_pubkey)
{'data_source_public_key': ..., 'hash_key': 'Qmd9RNRiyT6SUMPpxWJoRmZMVGEEMcBaPRKY6EdUGTvaLk'}
```

We can then take a look to our encrypted data by opening:

```
https://gateway.ipfs.io/ipfs/<your hash here>
```

A recipient can be deligated by provide their public key:

```
>>> policy_info = client.authorize(recipient_pubkeys=recipient_pubkeys, max_days=5)
```

Once eveything is ready, the recipient can now able to decrypt the file and download to the local machine:

```
>>> client.downloadFile(downloadFilename="downloadFile.txt",
        recipient_privkeys=recipient_privkeys, 
        receipt=receipt, 
        policy_info=policy_info)
```

## Documentation

More detailed information on NuCypher:

https://github.com/nucypher/nucypher


## License

This code is distributed under the terms of the [MIT license](https://opensource.org/licenses/MIT).  Details can be found in the file
[LICENSE](LICENSE) in this repository.

