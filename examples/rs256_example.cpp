#include <jwtxx/jwt.h>
#include <jwtxx/ios.h>

#include <iostream>
#include <cstdlib>

using namespace JWTXX;

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <private-key.pem> <public-key.pem>\n";
        return 1;
    }

    const char* privateKeyFile = argv[1];
    const char* publicKeyFile = argv[2];

    try
    {
        std::cout << "1. Creating JWT with claims...\n";
        JWT jwt(Algorithm::RS256, {{"sub", Value("user")}, {"iss", Value("madf")}});

        std::cout << "2. Signing token with private key...\n";
        auto token = jwt.token(privateKeyFile);
        std::cout << "   Token: " << token << "\n\n";

        std::cout << "3. Parsing and verifying token with public key...\n";
        JWT jwt2(token, Key(Algorithm::RS256, publicKeyFile));
        std::cout << "   Token is valid\n\n";

        std::cout << "4. Reading claims:\n";
        std::cout << "   Algorithm: " << algToString(jwt2.alg()) << "\n";
        std::cout << "   Subject:   " << jwt2.claim("sub") << "\n";
        std::cout << "   Issuer:    " << jwt2.claim("iss") << "\n";
        return 0;
    }
    catch (const JWT::Error& error)
    {
        std::cerr << "Error: " << error.what() << std::endl;
        return 1;
    }
}
