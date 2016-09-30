# jwtxx README

[![Build Status](https://travis-ci.org/madf/jwtxx.svg?branch=master)](https://travis-ci.org/madf/jwtxx)

[![JWT Logo](http://jwt.io/assets/logo.svg)](https://jwt.io/)

C++ library to work with JWT

## Dependencies

* cmake - build system.
* jansson - JSON parser.
* openssl - cryptography.
* boost (optional) - unit tests.

## Compilation and installation


```
$ mkdir build
$ cd build
$ cmake ..
$ make
```

## Documentation

### Supported algorithms

* none - no signature.
* HS256, HS384, HS512 - HMAC-based algorithms with SHA-256, SHA-384 and SHA-512 hash functions respectively. Use shared secret.
* RS256, RS384, RS512 - RSA-based algorithms with SHA-256, SHA-384 and SHA-512 hash functions respectively. Use PKI.
* ES256, ES384, ES512 - Algorithms based on elliptic curves digital signature with SHA-256, SHA-384 and SHA-512 hash functions respectively. Use PKI.

RSA and ECDSA keys should be in PEM format. Public keys can be in form of certificates.

[Library reference](https://madf.github.io/jwtxx/index.html)

### Examples

###### HS256

Key argument is a shared secret.

```c++
#include <iostream>

#include <jwtxx/jwt.h>

using namespace JWTXX;

int main()
{
    // Create
    JWT jwt(Algorithm::HS256, {{"sub", "user"}, {"iss", "madf"}});
    auto token = jwt.token("secret-key");

    // Parse
    try
    {
        JWT jwt2(token, Key(Algorithm::HS256, "secret-key"));
        std::cout << "Algorithm: " << algToString(jwt2.alg()) << "\n"
                  << "Subject:   " << jwt2.claim("sub") << "\n"
                  << "Issuer:    " << jwt2.claim("iss") << std::endl;
    }
    catch (const JWT::Error& error)
    {
        std::cerr << "Error parsing token: " << error.what() << std::endl;
    }

    return 0;
}
```

###### RS256

Key argument is either a private key (when you create a token) or a public key (when you parse it).

```c++
#include <iostream>

#include <jwtxx/jwt.h>

using namespace JWTXX;

int main()
{
    // Create
    JWT jwt(Algorithm::RS256, {{"sub", "user"}, {"iss", "madf"}});
    auto token = jwt.token("/path/to/private-key.pem");

    // Parse
    try
    {
        JWT jwt2(token, Key(Algorithm::RS256, "/path/to/public-key.pem"));
        std::cout << "Algorithm: " << algToString(jwt2.alg()) << "\n"
                  << "Subject:   " << jwt2.claim("sub") << "\n"
                  << "Issuer:    " << jwt2.claim("iss") << std::endl;
    }
    catch (const JWT::Error& error)
    {
        std::cerr << "Error parsing token: " << error.what() << std::endl;
    }

    return 0;
}
```

###### ES256

Essentially the same as RS256, but you need elliptic curve keys.

###### none

Key argument is not used. Token has no signature part.
