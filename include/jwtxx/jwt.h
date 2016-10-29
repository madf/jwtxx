#pragma once

/** @file jwt.h
 *  @brief Classes, constants and functions to work with JWT.
 */

#include <functional>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <stdexcept>

#include <ctime>

/** @namespace JWTXX
 *  @brief All classes, functions and constants are here.
 */
namespace JWTXX
{

/** @fn void enableOpenSSLErrors()
 *  @brief Enable OpenSSL human-readable error messages.
 *  You only need to call it once, in the beginning of your program.
 */
void enableOpenSSLErrors();

/** @enum Algorithm
 *  @brief JWT signature algorithms.
 */
enum class Algorithm {
    HS256, /**< HMAC-based signature with SHA-256 digest */
    HS384, /**< HMAC-based signature with SHA-384 digest */
    HS512, /**< HMAC-based signature with SHA-512 digest */
    RS256, /**< RSA-based signature with SHA-256 digest */
    RS384, /**< RSA-based signature with SHA-384 digest */
    RS512, /**< RSA-based signature with SHA-512 digest */
    ES256, /**< ECDSA-based signature with SHA-256 digest */
    ES384, /**< ECDSA-based signature with SHA-384 digest */
    ES512, /**< ECDSA-based signature with SHA-512 digest */
    none   /**< no signature */
};

/** @class Error
 *  @brief Base class for all exceptions in the library.
 */
struct Error : public std::runtime_error
{
    /** @brief Constructor. */
    explicit Error(const std::string& message) : runtime_error(message) {}
};

/** @fn std::string algToString(Algorithm alg)
 *  @brief Converts algorithm code into a string representation.
 *  @param alg algorithm code.
 *  @return string representation of the supplied code.
 */
std::string algToString(Algorithm alg);

/** @fn Algorithm stringToAlg(const std::string& value)
 *  @brief Converts algorithm name into algorithm code.
 *  @param value algorithm name.
 *  @return algorithm code for the supplied name.
 *  @throws Error
 *  @note Throws if the supplied name is not valid.
 */
Algorithm stringToAlg(const std::string& value);

/** @class Key
 *  @brief Represents signature algorithm
 *  Signs tokens and verifies token signatures.
 */
class Key
{
    public:
        /** @class Error
         *  @brief Key-specific exception.
         */
        struct Error : JWTXX::Error
        {
            /** @brief Constructor. */
            explicit Error(const std::string& message) : JWTXX::Error(message) {}
        };

        /** @brief Constructs key using the specified algorithm and data.
         *  @param alg signature algorithm;
         *  @param keyData a shared secret or a path to key file.
         */
        Key(Algorithm alg, const std::string& keyData);
        /** @brief Destructor. */
        ~Key();

        /** @brief Move constructor. */
        Key(Key&&);
        /** @brief Move assignment. */
        Key& operator=(Key&&);

        /** @brief Returns algorithm code used by the key. */
        Algorithm alg() const { return m_alg; }

        /** @brief Signs a chunk of memory.
         *  @param data a pointer to data for signing;
         *  @param size a size of data for signing.
         */
        std::string sign(const void* data, size_t size) const;
        /** @brief Verifies a signature of a chunk of memory.
         *  @param data a pointer to signed data;
         *  @param size a size of signed data;
         *  @param signature a signature to verify.
         */
        bool verify(const void* data, size_t size, const std::string& signature) const;

        /** @class */
        struct Impl;
    private:
        Algorithm m_alg;
        std::unique_ptr<Impl> m_impl;
};

/** @typedef Pairs
 *  @brief Header and claim container.
 */
typedef std::unordered_map<std::string, std::string> Pairs;

/** @typedef Validator
 *  @brief Validation function for claims.
 */
typedef std::function<bool (const Pairs&)> Validator;

/** @typedef Validators
 *  @brief A list of validators.
 */
typedef std::vector<Validator> Validators;

/** @namespace JWTXX::Validate
 *  @brief Validation functions are here.
 */
namespace Validate
{

/** @fn Validator exp(std::time_t now = std::time(nullptr))
 *  @brief Constructs validator for 'exp' claim.
 *  @param now current time, may be overriden.
 */
Validator exp(std::time_t now = std::time(nullptr));
/** @fn Validator nbf(std::time_t now = std::time(nullptr))
 *  @brief Constructs validator for 'nbf' claim.
 *  @param now current time, may be overriden.
 */
Validator nbf(std::time_t now = std::time(nullptr));
/** @fn Validator iat(std::time_t now = std::time(nullptr))
 *  @brief Constructs validator for 'iat' claim.
 *  @param now current time, may be overriden.
 */
Validator iat(std::time_t now = std::time(nullptr));
/** @fn Validator iss(std::string issuer)
 *  @brief Constructs validator for 'iss' claim.
 *  @param issuer valid issuer name.
 */
Validator iss(std::string issuer);
/** @fn Validator aud(std::string audience)
 *  @brief Constructs validator for 'aud' claim.
 *  @param audience valid audience.
 */
Validator aud(std::string audience);
/** @fn Validator sub(std::string subject)
 *  @brief Constructs validator for 'sub' claim.
 *  @param subject valid subject name.
 */
Validator sub(std::string subject);

}

/** @class JWT
 *  @brief Main class to work with JWT
 */
class JWT
{
    public:
        /** @class Error
         *  @brief JWT-specific exception.
         */
        struct Error : JWTXX::Error
        {
            /** @brief Constructor. */
            explicit Error(const std::string& message) : JWTXX::Error(message) {}
        };

        /** @class ParseError
         *  @brief Indicates problems with JWT structure.
         */
        struct ParseError : Error
        {
            /** @brief Constructor. */
            explicit ParseError(const std::string& message) : Error(message) {}
        };

        /** @class ValidationError
         *  @brief Indicates problems with JWT validation (signature and claims).
         */
        struct ValidationError : Error
        {
            /** @brief Constructor. */
            explicit ValidationError(const std::string& message) : Error(message) {}
        };

        /** @brief Constructs a JWT from a token.
         *  @param token the token;
         *  @param key key to use for signatire verification;
         *  @param validators an optional list of validators; validates 'exp' by default.
         */
        JWT(const std::string& token, Key key, Validators&& validators = {Validate::exp()});

        /** @brief Constructs a JWT from scratch.
         *  @param alg signature algorithm;
         *  @param claims a list of claims;
         *  @param header an optional list of header records; 'alg' and 'typ' can't be specified manually.
         */
        JWT(Algorithm alg, Pairs claims, Pairs header = Pairs());

        /** @brief Returns a JWT for a token without validation.
         *  @param token the token.
         */
        static JWT parse(const std::string& token);

        /** @brief Validates a token without constructing a JWT.
         *  @param token the token;
         *  @param key key to use for signatire verification;
         *  @param validators an optional list of validators; validates 'exp' by default.
         */
        static bool verify(const std::string& token, Key key, Validators&& validators = {Validate::exp()});

        /** @brief Returns an algorithm. */
        Algorithm alg() const { return m_alg; }

        /** @brief Returns a list of claims. */
        const Pairs& claims() const { return m_claims; }

        /** @brief Returns a list of header fields. */
        const Pairs& header() const { return m_header; }

        /** @brief Returns a value of a specific claim.
         *  @param name claim name.
         *  @note Returns an empty string if the claim is missing.
         */
        std::string claim(const std::string& name) const;

        /** @brief Returns a signed token.
         *  @param keyData key-specific data.
         *  @note Automatically constructs key using the algorithm specified in this JWT.
         */
        std::string token(const std::string& keyData) const;

    private:
        Algorithm m_alg;
        Pairs m_header;
        Pairs m_claims;
};

}
