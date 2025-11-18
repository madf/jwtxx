#include "json.h"

#include "jwtxx/jwt.h"

#include <unordered_map>
#include <memory> // std::unique_ptr
#include <utility> // std::pair<>::first, std::pair<>::second
#include <type_traits> // std::is_same_v, std::decay_t

#include <cstdlib> // free
#include <cstdint>

#include <jansson.h>

using JWTXX::Value;

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

Value arrayToValue(const json_t* node) noexcept;
Value objectToValue(const json_t* node) noexcept;

Value toValue(const json_t* node) noexcept
{
    switch (json_typeof(node))
    {
        case JSON_NULL: return Value{};
        case JSON_TRUE: return Value(true);
        case JSON_FALSE: return Value(false);
        case JSON_STRING: return Value(json_string_value(node));
        case JSON_INTEGER: return Value(static_cast<int64_t>(json_integer_value(node)));
        case JSON_REAL: return Value::number(json_real_value(node));
        case JSON_ARRAY: return arrayToValue(node);
        case JSON_OBJECT: return objectToValue(node);
    }
    return {}; // Just in case.
}

Value arrayToValue(const json_t* node) noexcept
{
    Value::Array array(json_array_size(node));
    for (size_t i = 0; i < array.size(); ++i)
        array[i] = toValue(json_array_get(node, i));
    return Value(std::move(array));
}

Value::Object toValueObject(const json_t* node) noexcept
{
    Value::Object object;
    auto* n = const_cast<json_t*>(node);
    for (auto* it = json_object_iter(n); it != nullptr; it = json_object_iter_next(n, it))
        object.emplace(json_object_iter_key(it), toValue(json_object_iter_value(it)));
    return object;
}

Value objectToValue(const json_t* node) noexcept
{
    return Value(toValueObject(node));
}

json_t* toJSONT(const Value& value) noexcept
{
    return value.visit([](auto&& v) -> json_t* {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, Value::Null>) {
            return json_null();
        } else if constexpr (std::is_same_v<T, bool>) {
            if (v)
                return json_true();
            return json_false();
        } else if constexpr (std::is_same_v<T, int64_t>) {
            return json_integer(v);
        } else if constexpr (std::is_same_v<T, std::string>) {
            return json_stringn(v.c_str(), v.length());
        } else if constexpr (std::is_same_v<T, Value::Array>) {
            auto* array = json_array();
            for (const auto& i : v)
                json_array_append_new(array, toJSONT(i));
            return array;
        } else if constexpr (std::is_same_v<T, Value::Object>) {
            auto* object = json_object();
            for (const auto& i : v)
                json_object_set_new(object, i.first.c_str(), toJSONT(i.second));
            return object;
        }
        return nullptr;
    });
}

}

std::string JWTXX::toJSON(const Value::Object& data) noexcept
{
    const JSON root(json_object());
    for (const auto& item : data)
        json_object_set_new(root.get(), item.first.c_str(), toJSONT(item.second));
    return dumpNode(root.get());
}

Value::Object JWTXX::fromJSON(const std::string& data)
{
    json_error_t error;
    const JSON root(json_loads(data.c_str(), 0, &error));
    if (!root)
        throw JWT::ParseError("Error parsing json at position " + std::to_string(error.position) + " in '" + data + "', reason: " + error.text);

    if (!json_is_object(root.get()))
        throw JWT::ParseError("Not a JSON object.");

    return toValueObject(root.get());
}
