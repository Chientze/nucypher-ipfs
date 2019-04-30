import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="nucypher-ipfs",
    version="0.0.5",
    author="Pisuth D.",
    author_email="pisuth.dae@gmail.com",
    description="Python SDK allows python developers to securely upload and download a file to IPFS, end-to-end encrypting data with keys from NuCypher network",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pisuthd/nucypher-ipfs",
    packages=setuptools.find_packages(),
    install_requires=[
          'ipfsapi',
          'nucypher',
          'Faker'
      ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)

