/**
 * @file rs256_example.cpp
 * @brief Example demonstrating RSA-SHA256 JWT creation and parsing
 *
 * This example shows:
 * - Creating a JWT with RSA-SHA256 algorithm
 * - Signing with a private RSA key
 * - Verifying with a public RSA key
 * - Accessing claims
 *
 * Note: This example requires RSA keys. You can generate them with:
 *   openssl genrsa -out private-key.pem 2048
 *   openssl rsa -in private-key.pem -pubout -out public-key.pem
 */

#include <jwtxx/jwt.h>
#include <jwtxx/ios.h>

#include <iostream>
#include <cstdlib>

using namespace JWTXX;

int main(int argc, char* argv[])
{
    std::cout << "=== RSA-SHA256 JWT Example ===\n\n";

    // Check for key file arguments
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <private-key.pem> <public-key.pem>\n";
        return 1;
    }

    const char* privateKeyFile = argv[1];
    const char* publicKeyFile = argv[2];

    try
    {
        // Create a JWT with RS256 algorithm
        std::cout << "1. Creating JWT with claims...\n";
        JWT jwt(Algorithm::RS256, {{"sub", Value("user")}, {"iss", Value("madf")}});

        // Sign with private key
        std::cout << "2. Signing token with private key...\n";
        auto token = jwt.token(privateKeyFile);
        std::cout << "   Token: " << token << "\n\n";

        // Parse and verify with public key
        std::cout << "3. Parsing and verifying token with public key...\n";
        JWT jwt2(token, Key(Algorithm::RS256, publicKeyFile));
        std::cout << "   Token is valid\n\n";

        std::cout << "4. Reading claims:\n";
        std::cout << "   Algorithm: " << algToString(jwt2.alg()) << "\n";
        std::cout << "   Subject:   " << jwt2.claim("sub") << "\n";
        std::cout << "   Issuer:    " << jwt2.claim("iss") << "\n";

        std::cout << "\n=== Example completed successfully ===\n";
        return 0;
    }
    catch (const JWT::Error& error)
    {
        std::cerr << "   Error: " << error.what() << std::endl;
        return 1;
    }
}
