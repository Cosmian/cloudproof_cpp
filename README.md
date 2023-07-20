# Cloudproof C/C++

C/C++ bindings for [Cosmian's Cloudproof Encryption](https://docs.cosmian.com/cloudproof_encryption/use_cases_benefits/).

Cloudproof Encryption secures data repositories and applications in the cloud with advanced application-level encryption and encrypted search.

<!-- toc -->

- [Licensing](#licensing)
- [Cryptographic primitives](#cryptographic-primitives)
- [Getting started](#getting-started)

<!-- tocstop -->

## Licensing

The library is available under a dual licensing scheme Affero GPL/v3 and commercial. See [LICENSE.md](LICENSE.md) for details.

## Cryptographic primitives

The library is based on:

- [CoverCrypt](https://github.com/Cosmian/cover_crypt) algorithm which allows
creating ciphertexts for a set of attributes and issuing user keys with access
policies over these attributes. `CoverCrypt` offers Post-Quantum resistance.

- [Findex](https://github.com/Cosmian/findex) which is a cryptographic protocol designed to securely make search queries on
an untrusted cloud server. Thanks to its encrypted indexes, large databases can
securely be outsourced without compromising usability.

## Getting started

To download the header files and libs run the following command:

```bash
./download_libs.sh
```

Code examples are available in [./examples](./examples) to get you started.

Please [check the online documentation](https://docs.cosmian.com/cloudproof_encryption/use_cases_benefits/) for more details on using the CloudProof APIs.

### Covercrypt

- Compile and run C example

```bash
gcc examples/covercrypt.c -o covercrypt_c -I include/ -L lib/ -lcloudproof
LD_LIBRARY_PATH=lib ./covercrypt_c
```

- Compile and run C++ example

```bash
g++ examples/covercrypt.cpp -o covercrypt_cpp -I include/ -L lib/ -lcloudproof
LD_LIBRARY_PATH=lib ./covercrypt_cpp
```
