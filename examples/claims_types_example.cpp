#include <jwtxx/jwt.h>
#include <jwtxx/ios.h>

#include <iostream>

using namespace JWTXX;

int main()
{
    std::cout << "1. Creating JWT with different claim types...\n";
    JWT jwt(Algorithm::HS256, {
        {"sub", Value("user123")},                                    // String
        {"admin", Value(true)},                                       // Boolean
        {"user_id", Value(int64_t(42))},                             // Integer
        {"quota", Value::number(99.5)},                              // Float
        {"roles", Value({Value("admin"), Value("user")})},           // Array
        {"metadata", Value({{"department", Value("engineering")}})}  // Object
    });

    auto token = jwt.token("secret-key");
    std::cout << "   Token created: " << token << "\n\n";

    std::cout << "2. Parsing token and accessing claims...\n";
    try
    {
        JWT parsed(token, Key(Algorithm::HS256, "secret-key"));
        std::cout << "   Token is valid\n\n";

        std::cout << "3. String claim:\n";
        auto sub = parsed.claim("sub");
        if (sub.isString())
            std::cout << "   Subject: " << sub.getString() << "\n\n";

        std::cout << "4. Boolean claim:\n";
        auto admin = parsed.claim("admin");
        if (admin.isBool())
            std::cout << "   Admin: " << (admin.getBool() ? "true" : "false") << "\n\n";

        std::cout << "5. Integer claim:\n";
        auto userId = parsed.claim("user_id");
        if (userId.isInteger())
            std::cout << "   User ID: " << userId.getInteger() << "\n\n";

        std::cout << "6. Float claim:\n";
        auto quota = parsed.claim("quota");
        std::cout << "   Quota: " << quota << "\n\n";

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

        std::cout << "8. Object claim:\n";
        auto metadata = parsed.claim("metadata");
        if (metadata.isObject())
        {
            auto metaObj = metadata.getObject();
            std::cout << "   Metadata:\n";
            for (const auto& [key, value] : metaObj)
                std::cout << "     " << key << ": " << value << "\n";
        }

        std::cout << "\n9. Accessing missing claim:\n";
        auto missing = parsed.claim("nonexistent");
        if (missing.isNull())
            std::cout << "   Claim 'nonexistent' not found (null)\n";

    }
    catch (const JWT::Error& error)
    {
        std::cerr << "Error: " << error.what() << std::endl;
        return -1;
    }

    return 0;
}
