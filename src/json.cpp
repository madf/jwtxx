#include "json.h"

#include <jansson.h>

using JWTXX::JWT;
using JWTXX::Pairs;

namespace
{

struct JSONDeleter
{
    void operator()(json_t* obj){ json_decref(obj); }
};
typedef std::unique_ptr<json_t, JSONDeleter> JSON;

std::string toString(const json_t* node)
{
    switch (json_typeof(node))
    {
        case JSON_NULL: return "NULL";
        case JSON_TRUE: return "true";
        case JSON_FALSE: return "false";
        case JSON_STRING: return json_string_value(node);
        case JSON_INTEGER: return std::to_string(json_integer_value(node));
        case JSON_REAL: return std::to_string(json_real_value(node));
        default: return json_dumps(node, JSON_COMPACT);
    }
    return {}; // Just in case.
}

}

std::string JWTXX::toJSON(const Pairs& data)
{
    JSON root(json_object());
    for (const auto& item : data)
        json_object_set_new(root.get(), item.first.c_str(), json_string(item.second.c_str()));
    char* dump = json_dumps(root.get(), JSON_COMPACT);
    std::string res(dump);
    free(dump);
    return res;
}

Pairs JWTXX::fromJSON(const std::string& data)
{
    json_error_t error;
    JSON root(json_loads(data.c_str(), 0, &error));
    if (!root)
        throw std::runtime_error("Error parsing json at position " + std::to_string(error.position) + " in '" + data + "', reason: " + error.text);

    if (!json_is_object(root.get()))
        throw std::runtime_error("Not a JSON object.");

    const char* key = nullptr;
    json_t* value = nullptr;
    Pairs res;
    json_object_foreach(root.get(), key, value)
    {
        res[key] = toString(value);
    }

    return res;
}
