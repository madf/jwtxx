#include "toolversion.h"

#include "json.h"
#include "base64url.h"
#include "utils.h"

#include <iostream>
#include <string>
#include <functional>

#include <jwtxx/jwt.h>
#include <jwtxx/version.h>

#include <cstring>
#include <cerrno>

#ifndef WIN32
    #include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>

namespace Utils = JWTXX::Utils;

namespace
{

std::string baseName(const std::string& path)
{
    auto pos = path.find_last_of('/');
    if (pos != std::string::npos)
        return path.substr(pos + 1, path.length() - pos - 1);
    return path;
}

void showHelp(const std::string& self)
{
    std::cout << "Usage: " << baseName(self) << " [option]...\n"
              << "Generate or verify JWT.\n\n"
              << "Options:\n\n"
              << "\t-h, --help            show help and exit\n"
              << "\t-v, --version         show version and exit\n"
              << "\t-a, --alg <algorithm> use the specified digital signature algorithm\n"
              << "\t-k, --key <filename>  use the specified file as a key for digital signature\n"
              << "\t-s, --sign <token>    sign data and produce a JWT\n"
              << "\t-V, --verify <token>  verify the supplied JWT\n"
              << "\t-p, --print <token>   show token contents\n";
}

void showVersion(const std::string& self)
{
    std::cout << baseName(self) << " " << JWTTool::version << "\n"
              << "libjwtxx " << JWTXX::version << "\n";
}

#ifdef WIN32
std::string modeName(unsigned short mode)
{
    switch (mode)
    {
        case S_IFREG: return "a regular file";
        case S_IFDIR: return "a directory";
        case S_IFCHR: return "a character device";
    }
    return "unknown filesystem entity with mode " + std::to_string(mode);
}
#else
std::string modeName(mode_t mode)
{
    switch (mode)
    {
        case S_IFSOCK: return "a socket";
        case S_IFLNK: return "a symbolic link";
        case S_IFREG: return "a regular file";
        case S_IFBLK: return "a block device";
        case S_IFDIR: return "a directory";
        case S_IFCHR: return "a character device";
        case S_IFIFO: return "a FIFO";
    }
    return "unknown filesystem entity with mode " + std::to_string(mode);
}
#endif

int noAction(JWTXX::Algorithm /*alg*/, const std::string& /*keyFile*/, const std::string& /*data*/)
{
    std::cerr << "No action specified. Use -s (--sign) to sign a token or -V (--verify) to verify a token or -p (--print) to print a token.\n";
    return -1;
}

int sign(JWTXX::Algorithm alg, const std::string& keyFile, const std::string& data)
{
    try
    {
        auto source = JWTXX::fromJSON(data);
        JWTXX::JWT jwt(alg, source);
        std::cout << jwt.token(keyFile) << "\n";
        return 0;
    }
    catch (const JWTXX::Error& ex)
    {
        std::cerr << ex.what() << "\n";
        return -1;
    }
}

int verify(JWTXX::Algorithm alg, const std::string& keyFile, const std::string& data)
{
    try
    {
        auto res = JWTXX::JWT::verify(data, JWTXX::Key(alg, keyFile));
        if (res)
        {
            std::cout << "The token is valid.\n";
            return 0;
        }
        std::cout << "The token is invalid. " << res.message() << "\n";
        return -1;
    }
    catch (const JWTXX::Error& ex)
    {
        std::cerr << ex.what() << "\n";
        return -1;
    }
}

void printPairs(const JWTXX::Pairs& pairs)
{
    std::cout << "{\n";
    bool first = true;
    for (const auto& header : pairs)
    {
        if (first)
            first = false;
        else
            std::cout << ",\n";
        std::cout << "\t\"" << header.first << "\": \"" << header.second << "\"";
    }
    std::cout << "\n}\n";
}

int print(JWTXX::Algorithm /*alg*/, const std::string& /*keyFile*/, const std::string& data)
{
    try
    {
        auto parts = Utils::split(data);
        JWTXX::Pairs header = JWTXX::fromJSON(JWTXX::Base64URL::decode(std::get<0>(parts)).toString());
        JWTXX::Pairs claims = JWTXX::fromJSON(JWTXX::Base64URL::decode(std::get<1>(parts)).toString());
        printPairs(header);
        std::cout << ".\n";
        printPairs(claims);
        return 0;
    }
    catch (const JWTXX::Error& ex)
    {
        std::cerr << ex.what() << "\n";
        return -1;
    }
}

typedef std::function<int (JWTXX::Algorithm, const std::string&, const std::string&)> Action;

}

int main(int argc, char* argv[])
{
    JWTXX::Algorithm alg = JWTXX::Algorithm::none;
    std::string keyFile;
    std::string data;
    Action action = noAction;
    for (int i = 0; i < argc; ++i)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            showHelp(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0)
        {
            showVersion(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--alg") == 0)
        {
            if (i + 1 == argc)
            {
                std::cerr << argv[i] << " needs and argument - algorithm name.\n";
                return -1;
            }
            try
            {
                alg = JWTXX::stringToAlg(argv[++i]);
            }
            catch (const JWTXX::Error& ex)
            {
                std::cerr << ex.what() << "\n";
                return -1;
            }
        }
        else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0)
        {
            if (i + 1 == argc)
            {
                std::cerr << argv[i] << " needs and argument - key file name.\n";
                return -1;
            }
            keyFile = argv[++i];
            struct stat sb;
            if (stat(keyFile.c_str(), &sb) == -1)
            {
                std::cerr << "Can't access file '" << keyFile << "'. Error: " << strerror(errno) << "\n";
                return -1;
            }
            if ((sb.st_mode & S_IFMT) != S_IFREG)
            {
                std::cerr << "Key file should be a regular file. '" << keyFile << "' is a " << modeName(sb.st_mode & S_IFMT) << ".\n";
                return -1;
            }
        }
        else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--sign") == 0)
        {
            if (i + 1 == argc)
            {
                std::cerr << argv[i] << " needs and argument - a token.\n";
                return -1;
            }
            data = argv[++i];
            action = sign;
        }
        else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--verify") == 0)
        {
            if (i + 1 == argc)
            {
                std::cerr << argv[i] << " needs and argument - a token.\n";
                return -1;
            }
            data = argv[++i];
            action = verify;
        }
        else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--print") == 0)
        {
            if (i + 1 == argc)
            {
                std::cerr << argv[i] << " needs and argument - a token.\n";
                return -1;
            }
            data = argv[++i];
            action = print;
        }
    }
    return action(alg, keyFile, data);
}
