#include <jwtxx/jwt.h>
#include <jwtxx/ios.h>

#include <iostream>
#include <ctime>

using namespace JWTXX;

int main()
{
    auto now = std::time(nullptr);
    auto future = now + 3600;  // 1 hour from now

    std::cout << "1. Creating JWT with time-based and string claims...\n";
    JWT jwt(Algorithm::HS256, {
        {"iss", Value("myapp")},
        {"sub", Value("user123")},
        {"aud", Value("api")},
        {"iat", Value(static_cast<int64_t>(now))},
        {"nbf", Value(static_cast<int64_t>(now))},
        {"exp", Value(static_cast<int64_t>(future))}
    });

    auto token = jwt.token("secret-key");
    std::cout << "   Token created\n\n";

    std::cout << "2. Validating with default validator (exp)...\n";
    try
    {
        JWT jwt1(token, Key(Algorithm::HS256, "secret-key"));
        std::cout << "   Token is valid (not expired)\n\n";
    }
    catch (const JWT::ValidationError& e)
    {
        std::cerr << "   Validation failed: " << e.what() << "\n\n";
    }

    std::cout << "3. Validating with multiple validators...\n";
    try
    {
        JWT jwt2(token, Key(Algorithm::HS256, "secret-key"), {
            Validate::exp(now + 7200),  // Token should be valid for 2 hours from now
            Validate::nbf(now + 7200),  // Token should be valid 2 hours from now
            Validate::iat(now + 7200),  // Token should have been issued before 2 hours from now
            Validate::iss("myapp"),     // Check issuer
            Validate::sub("user123"),   // Check subject
            Validate::aud("api")        // Check audience
        });
        std::cout << "   All validations passed\n\n";
    }
    catch (const JWT::ValidationError& e)
    {
        std::cerr << "   Validation failed: " << e.what() << "\n\n";
    }

    std::cout << "4. Testing validation failure (wrong issuer)...\n";
    try
    {
        JWT jwt3(token, Key(Algorithm::HS256, "secret-key"), {
            Validate::iss("wrongapp")  // Wrong issuer
        });
        std::cout << "   This shouldn't happen\n\n";
    }
    catch (const JWT::ValidationError& e)
    {
        std::cout << "   Expected validation error: " << e.what() << "\n\n";
    }

    std::cout << "5. Using verify() method (non-throwing)...\n";
    auto result = JWT::verify(token, Key(Algorithm::HS256, "secret-key"), {
        Validate::exp(now + 7200),
        Validate::iss("myapp")
    });

    if (result)
        std::cout << "   Token is valid\n";
    else
        std::cout << "   Token is invalid: " << result.message() << "\n";
    return 0;
}
