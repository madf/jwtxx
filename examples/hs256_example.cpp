#include <jwtxx/jwt.h>
#include <jwtxx/ios.h>

#include <iostream>

using namespace JWTXX;

int main()
{
    std::cout << "1. Creating JWT with claims...\n";
    JWT jwt(Algorithm::HS256, {{"sub", Value("user")}, {"iss", Value("madf")}});

    std::cout << "2. Signing token...\n";
    auto token = jwt.token("secret-key");
    std::cout << "   Token: " << token << "\n\n";

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
        std::cerr << "Error: " << error.what() << std::endl;
        return -1;
    }
    return 0;
}
