/**
 * @file key_reuse_example.cpp
 * @brief Example demonstrating key reuse for better performance
 *
 * This example shows:
 * - Creating a Key object once
 * - Reusing it to generate multiple tokens
 *
 * This is especially important for RSA/ECDSA keys where file I/O
 * and key parsing can be expensive.
 */

#include <jwtxx/jwt.h>

#include <iostream>
#include <vector>
#include <chrono>

using namespace JWTXX;

int main(int argc, char* argv[])
{
    std::cout << "=== Key Reuse Performance Example ===\n\n";

    // Check for key file arguments
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <private-key.pem>\n";
        return 1;
    }

    const char* privateKeyFile = argv[1];

    // Create a key object once
    std::cout << "1. Creating Key object (one-time operation)...\n";
    Key key(Algorithm::RS256, privateKeyFile);
    std::cout << "   Key created\n\n";

    // Simulate multiple users
    std::vector<std::string> users;
    for (size_t i = 0; i < 20; ++i)
        users.push_back("user" + std::to_string(i + 1));

    std::cout << "2. Generating tokens for " << users.size() << " users...\n\n";

    auto start = std::chrono::steady_clock::now();

    for (const auto& user : users)
    {
        // Create JWT with user-specific claims
        JWT jwt(key.alg(), {{"sub", Value(user)}, {"iss", Value("madf")}});

        // Reuse the key - no file I/O, no key re-parsing
        auto token = jwt.token(key);

        std::cout << "   - " << user << ": " << token.substr(0, 50) << "...\n";
    }

    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    std::cout << "3. Performance:\n";
    std::cout << "   Generated " << users.size() << " tokens in "
              << duration.count() << " microseconds\n";
    std::cout << "   Average: " << duration.count() / users.size()
              << " microseconds per token\n\n";

    std::cout << "4. Generating tokens for " << users.size() << " users (no key reuse)...\n\n";

    start = std::chrono::steady_clock::now();

    for (const auto& user : users)
    {
        // Create JWT with user-specific claims
        JWT jwt(Algorithm::RS256, {{"sub", Value(user)}, {"iss", Value("madf")}});

        // No key reuse
        auto token = jwt.token(privateKeyFile);

        std::cout << "   - " << user << ": " << token.substr(0, 50) << "...\n";
    }

    end = std::chrono::steady_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    std::cout << "5. Performance:\n";
    std::cout << "   Generated " << users.size() << " tokens in "
              << duration.count() << " microseconds\n";
    std::cout << "   Average: " << duration.count() / users.size()
              << " microseconds per token\n\n";

    std::cout << "\n=== Example completed successfully ===\n";
    return 0;
}
