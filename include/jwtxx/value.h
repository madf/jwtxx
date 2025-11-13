#pragma once

#include "error.h"

#include <variant>
#include <string>
#include <vector>
#include <unordered_map>
#include <numeric> // std::accumulate
#include <type_traits> // std::decay_t, std::is_same_v
#include <utility> // std::move
#include <cstdint> // int64_t

namespace JWTXX
{

class Value
{
    public:
        /** @class Error
         *  @brief JWT-specific exception.
         */
        struct Error : JWTXX::Error
        {
            /** @brief Constructor.
             *  @param message error message.
             */
            explicit Error(const std::string& message) noexcept : JWTXX::Error(message) {}
        };

        struct Null {};
        using Array = std::vector<Value>;
        using Object = std::unordered_map<std::string, Value>;

        Value() noexcept : m_value(Null{}) {} // null
        explicit Value(bool v) noexcept : m_value(v) {} // Boolean
        explicit Value(int64_t v) noexcept : m_value(v) {} // Number
        // Intentionall non-explicit
        Value(const char* v) noexcept : m_value(std::string(v)) {}
        explicit Value(std::string v) noexcept : m_value(std::move(v)) {} // String
        explicit Value(std::initializer_list<Array::value_type> vs) noexcept : m_value(Array(std::move(vs))) {} // Array
        explicit Value(Array v) noexcept : m_value(std::move(v)) {}
        explicit Value(std::initializer_list<Object::value_type> vs) noexcept : m_value(Object(std::move(vs))) {} // Object
        explicit Value(Object v) noexcept : m_value(std::move(v)) {}

        static Value number(double v) noexcept { return Value(std::in_place, V{v}); } // Floating point

        Value(const Value&) = default;
        Value(Value&&) = default;
        Value& operator=(const Value&) = default;
        Value& operator=(Value&&) = default;
        ~Value() = default;

        bool isNull() const noexcept { return std::holds_alternative<Null>(m_value); }
        bool isBool() const noexcept { return std::holds_alternative<bool>(m_value); }
        bool isInteger() const noexcept { return std::holds_alternative<int64_t>(m_value); }
        bool isString() const noexcept { return std::holds_alternative<std::string>(m_value); }
        bool isArray() const noexcept { return std::holds_alternative<Array>(m_value); }
        bool isObject() const noexcept { return std::holds_alternative<Object>(m_value); }

        bool getBool() const { return get<bool>("Not a boolean value"); }
        int64_t getInteger() const { return get<int64_t>("Not an integer value"); }
        std::string getString() const { return get<std::string>("Not a string value"); }
        Array getArray() const { return get<Array>("Not an array value"); }
        Object getObject() const { return get<Object>("Not an object value"); }

        std::string toString() const;

        template <typename F>
        auto visit(F&& f) const { return std::visit(f, m_value); }
    private:
        using V = std::variant<Null, bool, int64_t, std::string, Array, Object, double>;

        V m_value;

        Value(std::in_place_t /*tag*/, V&& v) noexcept : m_value(std::move(v)) {}

        template <typename T>
        T get(const std::string& onError) const
        {
            const auto* res = std::get_if<T>(&m_value);
            if (res == nullptr)
                throw Error(onError);
            return *res;
        }
};

inline
std::string Value::toString() const
{
    return std::visit([](auto&& v) -> std::string {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, Null>) {
            return "null";
        } else if constexpr (std::is_same_v<T, bool>) {
            if (v)
                return "true";
            return "false";
        } else if constexpr (std::is_same_v<T, std::string>) {
            return "\"" + v + "\"";
        } else if constexpr (std::is_same_v<T, Array>) {
            return "[" +
                std::accumulate(v.begin(), v.end(), std::string{}, [](const auto& a, const auto& i){
                    if (a.empty())
                        return i.toString();
                    return a + "," + i.toString();
                }) +
                "]";
        } else if constexpr (std::is_same_v<T, Object>) {
            return "{" +
                std::accumulate(v.begin(), v.end(), std::string{}, [](const auto& a, const auto& i){
                    if (a.empty())
                        return "\"" + i.first + "\":" + i.second.toString();
                    return a + ",\"" + i.first + "\":" + i.second.toString();
                }) +
                "}";
        } else {
            return std::to_string(v);
        }
    }, m_value);
}

}
