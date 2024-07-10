#include "json.h"

#include <unordered_map>
#include <memory> // std::unique_ptr
#include <utility> // std::pair<>::first, std::pair<>::second

#include <cstdlib> // free

#include <jansson.h>

using JWTXX::Pairs;

namespace
{

struct JSONDeleter
{
    void operator()(json_t* obj) const noexcept { json_decref(obj); }
};
using JSON = std::unique_ptr<json_t, JSONDeleter>;

std::string dumpNode(const json_t* node) noexcept
{
    char* dump = json_dumps(node, JSON_COMPACT);
    std::string res(dump != nullptr ? dump : "");
    free(dump);
    return res;
}

std::string toString(const json_t* node) noexcept
{
    switch (json_typeof(node))
    {
        case JSON_NULL: return "NULL";
        case JSON_TRUE: return "true";
        case JSON_FALSE: return "false";
        case JSON_STRING: return json_string_value(node);
        case JSON_INTEGER: return std::to_string(json_integer_value(node));
        case JSON_REAL: return std::to_string(json_real_value(node));
        default: return dumpNode(node);
    }
    return {}; // Just in case.
}

}

std::string JWTXX::toJSON(const Pairs& data) noexcept
{
    const JSON root(json_object());
    for (const auto& item : data)
        json_object_set_new(root.get(), item.first.c_str(), json_string(item.second.c_str()));
    return dumpNode(root.get());
}

Pairs JWTXX::fromJSON(const std::string& data)
{
    json_error_t error;
    const JSON root(json_loads(data.c_str(), 0, &error));
    if (!root)
        throw JWT::ParseError("Error parsing json at position " + std::to_string(error.position) + " in '" + data + "', reason: " + error.text);

    if (!json_is_object(root.get()))
        throw JWT::ParseError("Not a JSON object.");

    const char* key = nullptr;
    json_t* value = nullptr;
    Pairs res;
    json_object_foreach(root.get(), key, value)
    {
        res[key] = toString(value);
    }

    return res;
}
