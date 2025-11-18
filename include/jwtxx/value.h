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

/** @class Value
 *  @brief Represents a JSON value that can hold any JSON type.
 *
 *  Value can hold null, boolean, integer, floating point number, string, array, or object.
 *  Provides type-safe access with runtime type checking.
 */
class Value
{
    public:
        /** @class Error
         *  @brief Value-specific exception.
         */
        struct Error : JWTXX::Error
        {
            /** @brief Constructor.
             *  @param message error message.
             */
            explicit Error(const std::string& message) noexcept : JWTXX::Error(message) {}
        };

        /** @struct Null
         *  @brief Represents a JSON null value.
         */
        struct Null {};

        /** @typedef Array
         *  @brief Represents a JSON array (vector of Values).
         */
        using Array = std::vector<Value>;

        /** @typedef Object
         *  @brief Represents a JSON object (string to Value map).
         */
        using Object = std::unordered_map<std::string, Value>;

        /** @brief Default constructor. Creates a null value. */
        Value() noexcept : m_value(Null{}) {}

        /** @brief Boolean constructor.
         *  @param v boolean value.
         */
        explicit Value(bool v) noexcept : m_value(v) {}

        /** @brief Integer constructor.
         *  @param v 64-bit integer value.
         */
        explicit Value(int64_t v) noexcept : m_value(v) {}

        /** @brief C-string constructor.
         *  @param v null-terminated C string.
         */
        explicit Value(const char* v) noexcept : m_value(std::string(v)) {}

        /** @brief String constructor.
         *  @param v string value.
         */
        explicit Value(std::string v) noexcept : m_value(std::move(v)) {}

        /** @brief Array initializer list constructor.
         *  @param vs initializer list of array elements.
         */
        explicit Value(std::initializer_list<Array::value_type> vs) noexcept : m_value(Array(std::move(vs))) {}

        /** @brief Array constructor.
         *  @param v array value.
         */
        explicit Value(Array v) noexcept : m_value(std::move(v)) {}

        /** @brief Object initializer list constructor.
         *  @param vs initializer list of object key-value pairs.
         */
        explicit Value(std::initializer_list<Object::value_type> vs) noexcept : m_value(Object(std::move(vs))) {}

        /** @brief Object constructor.
         *  @param v object value.
         */
        explicit Value(Object v) noexcept : m_value(std::move(v)) {}

        /** @brief Creates a floating point number Value.
         *  @param v double-precision floating point value.
         *  @return Value containing the floating point number.
         *  @note Use this static method to create floating point values.
         */
        static Value number(double v) noexcept { return Value(std::in_place, V{v}); }

        /** @brief Copy constructor. */
        Value(const Value&) = default;

        /** @brief Move constructor. */
        Value(Value&&) = default;

        /** @brief Copy assignment operator. */
        Value& operator=(const Value&) = default;

        /** @brief Move assignment operator. */
        Value& operator=(Value&&) = default;

        /** @brief Destructor. */
        ~Value() = default;

        /** @brief Checks if the value is null.
         *  @return true if the value is null, false otherwise.
         */
        bool isNull() const noexcept { return std::holds_alternative<Null>(m_value); }

        /** @brief Checks if the value is a boolean.
         *  @return true if the value is a boolean, false otherwise.
         */
        bool isBool() const noexcept { return std::holds_alternative<bool>(m_value); }

        /** @brief Checks if the value is an integer.
         *  @return true if the value is an integer, false otherwise.
         */
        bool isInteger() const noexcept { return std::holds_alternative<int64_t>(m_value); }

        /** @brief Checks if the value is a string.
         *  @return true if the value is a string, false otherwise.
         */
        bool isString() const noexcept { return std::holds_alternative<std::string>(m_value); }

        /** @brief Checks if the value is an array.
         *  @return true if the value is an array, false otherwise.
         */
        bool isArray() const noexcept { return std::holds_alternative<Array>(m_value); }

        /** @brief Checks if the value is an object.
         *  @return true if the value is an object, false otherwise.
         */
        bool isObject() const noexcept { return std::holds_alternative<Object>(m_value); }

        /** @brief Gets the boolean value.
         *  @return the boolean value.
         *  @throws Error if the value is not a boolean.
         */
        bool getBool() const { return get<bool>("Not a boolean value"); }

        /** @brief Gets the integer value.
         *  @return the 64-bit integer value.
         *  @throws Error if the value is not an integer.
         */
        int64_t getInteger() const { return get<int64_t>("Not an integer value"); }

        /** @brief Gets the string value.
         *  @return the string value.
         *  @throws Error if the value is not a string.
         */
        std::string getString() const { return get<std::string>("Not a string value"); }

        /** @brief Gets the array value.
         *  @return the array value.
         *  @throws Error if the value is not an array.
         */
        Array getArray() const { return get<Array>("Not an array value"); }

        /** @brief Gets the object value.
         *  @return the object value.
         *  @throws Error if the value is not an object.
         */
        Object getObject() const { return get<Object>("Not an object value"); }

        /** @brief Converts the value to its JSON string representation.
         *  @return JSON string representation of the value.
         *  @note Strings are returned with surrounding quotes, objects with braces, arrays with brackets.
         */
        std::string toString() const;

        /** @brief Applies a visitor function to the value.
         *  @tparam F visitor function type.
         *  @param f visitor function to apply.
         *  @return result of applying the visitor.
         */
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
