/**
 * @file claims_types_example.cpp
 * @brief Example demonstrating different claim value types
 *
 * This example shows:
 * - Using different JSON types in claims (string, boolean, integer, array, object)
 * - Type checking before accessing values
 * - Claim access
 */

#include <jwtxx/jwt.h>
#include <jwtxx/ios.h>

#include <iostream>

using namespace JWTXX;

int main()
{
    std::cout << "=== JWT Claims with Different Types ===\n\n";

    // Create JWT with various claim types
    std::cout << "1. Creating JWT with different value types...\n";
    JWT jwt(Algorithm::HS256, {
        {"sub", Value("user123")},                                    // String
        {"admin", Value(true)},                                       // Boolean
        {"user_id", Value(int64_t(42))},                             // Integer
        {"quota", Value::number(99.5)},                              // Float
        {"roles", Value({Value("admin"), Value("user")})},           // Array
        {"metadata", Value({{"department", Value("engineering")}})}  // Object
    });

    auto token = jwt.token("secret-key");
    std::cout << "   Token created\n\n";

    // Parse and access different types
    std::cout << "2. Parsing token and accessing claims...\n";
    try
    {
        JWT parsed(token, Key(Algorithm::HS256, "secret-key"));
        std::cout << "   Token is valid\n\n";

        // String claim
        std::cout << "3. String claim:\n";
        auto sub = parsed.claim("sub");
        if (sub.isString())
            std::cout << "   Subject: " << sub.getString() << "\n\n";

        // Boolean claim
        std::cout << "4. Boolean claim:\n";
        auto admin = parsed.claim("admin");
        if (admin.isBool())
            std::cout << "   Admin: " << (admin.getBool() ? "true" : "false") << "\n\n";

        // Integer claim
        std::cout << "5. Integer claim:\n";
        auto userId = parsed.claim("user_id");
        if (userId.isInteger())
            std::cout << "   User ID: " << userId.getInteger() << "\n\n";

        // Float claim
        std::cout << "6. Float claim:\n";
        auto quota = parsed.claim("quota");
        std::cout << "   Quota: " << quota << "\n\n";

        // Array claim
        std::cout << "7. Array claim:\n";
        auto roles = parsed.claim("roles");
        if (roles.isArray())
        {
            auto rolesArray = roles.getArray();
            std::cout << "   Roles (" << rolesArray.size() << " items):\n";
            for (const auto& role : rolesArray)
                std::cout << "     - " << role << "\n";
            std::cout << "\n";
        }

        // Object claim
        std::cout << "8. Object claim:\n";
        auto metadata = parsed.claim("metadata");
        if (metadata.isObject())
        {
            auto metaObj = metadata.getObject();
            std::cout << "   Metadata:\n";
            for (const auto& [key, value] : metaObj)
                std::cout << "     " << key << ": " << value << "\n";
        }

        // Missing claim
        std::cout << "\n9. Accessing missing claim:\n";
        auto missing = parsed.claim("nonexistent");
        if (missing.isNull())
            std::cout << "   Claim 'nonexistent' not found (null)\n";

    }
    catch (const JWT::Error& error)
    {
        std::cerr << "   Error: " << error.what() << std::endl;
        return 1;
    }

    std::cout << "\n=== Example completed successfully ===\n";
    return 0;
}
