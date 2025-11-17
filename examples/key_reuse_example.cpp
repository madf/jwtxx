#include <jwtxx/jwt.h>

#include <iostream>
#include <vector>
#include <chrono>

using namespace JWTXX;

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <private-key.pem>\n";
        return -1;
    }

    const char* privateKeyFile = argv[1];

    std::cout << "1. Creating Key object (one-time operation)...\n";
    Key key(Algorithm::RS256, privateKeyFile);
    std::cout << "   Key created\n\n";

    std::vector<std::string> users;
    for (size_t i = 0; i < 20; ++i)
        users.push_back("user" + std::to_string(i + 1));

    std::cout << "2. Generating tokens for " << users.size() << " users...\n\n";

    auto start = std::chrono::steady_clock::now();

    for (const auto& user : users)
    {
        JWT jwt(key.alg(), {{"sub", Value(user)}, {"iss", Value("madf")}});

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
        JWT jwt(Algorithm::RS256, {{"sub", Value(user)}, {"iss", Value("madf")}});

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
    return 0;
}
