/**
 * @file hs256_example.cpp
 * @brief Example demonstrating HMAC-SHA256 JWT creation and parsing
 *
 * This example shows:
 * - Creating a JWT with HMAC-SHA256 algorithm
 * - Signing with a shared secret
 * - Parsing and verifying the token
 * - Accessing claims
 */

#include <jwtxx/jwt.h>
#include <jwtxx/ios.h>

#include <iostream>

using namespace JWTXX;

int main()
{
    std::cout << "=== HMAC-SHA256 JWT Example ===\n\n";

    // Create a JWT with HS256 algorithm
    std::cout << "1. Creating JWT with claims...\n";
    JWT jwt(Algorithm::HS256, {{"sub", Value("user")}, {"iss", Value("madf")}});

    // Sign the JWT with a shared secret
    std::cout << "2. Signing token...\n";
    auto token = jwt.token("secret-key");
    std::cout << "   Token: " << token << "\n\n";

    // Parse and verify the token
    std::cout << "3. Parsing and verifying token...\n";
    try
    {
        JWT jwt2(token, Key(Algorithm::HS256, "secret-key"));
        std::cout << "   Token is valid\n\n";

        std::cout << "4. Reading claims:\n";
        std::cout << "   Algorithm: " << algToString(jwt2.alg()) << "\n";
        std::cout << "   Subject:   " << jwt2.claim("sub") << "\n";
        std::cout << "   Issuer:    " << jwt2.claim("iss") << "\n";
    }
    catch (const JWT::Error& error)
    {
        std::cerr << "   Error: " << error.what() << std::endl;
        return 1;
    }

    std::cout << "\n=== Example completed successfully ===\n";
    return 0;
}
