# Migration Guide: jwtxx 1.x to 2.x

This guide helps you upgrade your code from jwtxx 1.x to 2.x.

## What Changed in 2.0?

Version 2.0 introduces **JSON values** for JWT claims, replacing the string-only approach in 1.x. This allows you to use arbitrary JSON types (numbers, booleans, arrays, objects) in your claims, not just strings.

gcc-11 is no longer supported sue to bug in standard library implementation.

### Breaking Changes

1. **Claims now use `Value` type instead of `std::string`**
2. **Header fields now use `Value` type instead of `std::string`**
3. **Requires gcc-12 or later**

### New Features

- Support for all JSON types in claims (null, boolean, integer, float, string, array, object)
- Better performance through key reuse

### Non-Breaking Changes

- Fixed ECDSA signature generation
- Added constant-time comparison for HMAC signatures (security fix)
- Improved error handling for Base64 encoding/decoding
- New `token(const Key&)` overload for better performance

---

## Detailed Migration Guide

### 1. Creating JWTs with Claims

#### Before (1.x):
```cpp
#include <jwtxx/jwt.h>

using namespace JWTXX;

// Claims were strings
JWT jwt(Algorithm::HS256, {{"sub", "user123"}, {"iss", "myapp"}});
auto token = jwt.token("secret-key");
```

#### After (2.x):
```cpp
#include <jwtxx/jwt.h>

using namespace JWTXX;

// Claims are now Value objects - use explicit Value() constructor
JWT jwt(Algorithm::HS256, {{"sub", Value("user123")}, {"iss", Value("myapp")}});
auto token = jwt.token("secret-key");
```

**Migration tip:** Wrap all string literals in `Value()` constructor.

---

### 2. Reading Claims from JWTs

#### Before (1.x):
```cpp
JWT jwt(token, Key(Algorithm::HS256, "secret-key"));

// claim() returned std::string directly
std::string subject = jwt.claim("sub");
std::string issuer = jwt.claim("iss");

std::cout << "Subject: " << subject << "\n";
std::cout << "Issuer: " << issuer << "\n";
```

#### After (2.x) - Option 1: Using getString():
```cpp
JWT jwt(token, Key(Algorithm::HS256, "secret-key"));

// claim() returns Value - use getString() to extract
std::string subject = jwt.claim("sub").getString();
std::string issuer = jwt.claim("iss").getString();

std::cout << "Subject: " << subject << "\n";
std::cout << "Issuer: " << issuer << "\n";
```

#### After (2.x) - Option 2: Using stream operators:
```cpp
#include <jwtxx/jwt.h>
#include <jwtxx/ios.h>  // For stream operators

JWT jwt(token, Key(Algorithm::HS256, "secret-key"));

// Value can be streamed directly
std::cout << "Subject: " << jwt.claim("sub") << "\n";
std::cout << "Issuer: " << jwt.claim("iss") << "\n";
```

**Migration tip:** If you just need to print claims, use the stream operators. If you need the actual string value, use `.getString()`.

---

### 3. Working with Non-String Claims (new in 2.x)

One of the main benefits of 2.x is support for all JSON types:

```cpp
#include <jwtxx/jwt.h>

using namespace JWTXX;

// Create JWT with different value types
JWT jwt(Algorithm::HS256, {
    {"sub", Value("user123")},           // String
    {"admin", Value(true)},              // Boolean
    {"user_id", Value(int64_t(42))},     // Integer
    {"quota", Value::number(99.5)},      // Float (use static method)
    {"roles", Value({Value("admin"), Value("user")})},  // Array
    {"metadata", Value({{"key", Value("value")}})}      // Object
});

auto token = jwt.token("secret-key");

// Parse and access different types
JWT parsed(token, Key(Algorithm::HS256, "secret-key"));

std::string sub = parsed.claim("sub").getString();     // "user123"
bool admin = parsed.claim("admin").getBool();          // true
int64_t uid = parsed.claim("user_id").getInteger();   // 42
auto roles = parsed.claim("roles").getArray();         // Array of Values
auto meta = parsed.claim("metadata").getObject();      // Object (map)
```

**Migration benefit:** You can now use native types instead of converting everything to/from strings.

---

### 4. Checking Claim Types

2.x provides type checking methods:

```cpp
JWT jwt(token, Key(Algorithm::HS256, "secret-key"));
auto claim = jwt.claim("user_id");

if (claim.isInteger()) {
    int64_t id = claim.getInteger();
    std::cout << "User ID: " << id << "\n";
} else if (claim.isString()) {
    std::string id = claim.getString();
    std::cout << "User ID (as string): " << id << "\n";
}

// Available type checkers:
// - isNull()
// - isBool()
// - isInteger()
// - isString()
// - isArray()
// - isObject()
```

---

### 5. Missing Claims

#### Before (1.x):
```cpp
std::string claim = jwt.claim("missing");  // Returns empty string
```

#### After (2.x):
```cpp
Value claim = jwt.claim("missing");  // Returns null Value

if (claim.isNull()) {
    std::cout << "Claim not found\n";
}

// Or check before accessing
if (!jwt.claim("missing").isNull()) {
    std::string value = jwt.claim("missing").getString();
}
```

**Migration tip:** Check with `.isNull()` before accessing to avoid errors.

---

### 6. Performance: Key Reuse (new in 2.x)

If you're generating many tokens, 2.x allows key reuse for better performance:

#### Before (1.x):
```cpp
// Key created and parsed on every iteration
for (const auto& user : users) {
    JWT jwt(Algorithm::RS256, {{"sub", user}});
    auto token = jwt.token("/path/to/key.pem");  // Reads file every time
}
```

#### After (2.x):
```cpp
// Create key once, reuse many times
Key key(Algorithm::RS256, "/path/to/key.pem");  // Read file once

for (const auto& user : users) {
    JWT jwt(Algorithm::RS256, {{"sub", Value(user)}});
    auto token = jwt.token(key);  // Reuse key
}
```

**Performance improvement:** faster for bulk token generation.

---

## Error Handling

### Getting Wrong Type

```cpp
JWT jwt(token, Key(Algorithm::HS256, "secret-key"));

try {
    // If "admin" is boolean but you try to get as string
    std::string admin = jwt.claim("admin").getString();
} catch (const Value::Error& e) {
    std::cerr << "Type error: " << e.what() << "\n";
    // Output: "Not a string value"
}
```

**Best practice:** Use type checkers (`isString()`, `isBool()`, etc.) before accessing.
