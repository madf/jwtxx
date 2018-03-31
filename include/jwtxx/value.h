#pragma once

#include <unordered_map>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstdint>

namespace JWTXX
{

class Value;

struct Null {};
using Array = std::vector<Value>;
using Object = std::unordered_map<std::string, Value>;

namespace Impl
{

enum class TypeTag { object, array, string, integer, real, boolean, null, unknown };

template <typename T> inline TypeTag typeTag() noexcept { return TypeTag::unknown; }
template <typename T> inline std::string typeName() noexcept { return tagName(typeTag<T>()); }

template <> inline TypeTag typeTag<Object>() noexcept { return TypeTag::object; }
template <> inline TypeTag typeTag<Array>() noexcept { return TypeTag::array; }
template <> inline TypeTag typeTag<std::string>() noexcept { return TypeTag::string; }
template <> inline TypeTag typeTag<int64_t>() noexcept { return TypeTag::integer; }
template <> inline TypeTag typeTag<double>() noexcept { return TypeTag::real; }
template <> inline TypeTag typeTag<bool>() noexcept { return TypeTag::boolean; }
template <> inline TypeTag typeTag<Null>() noexcept { return TypeTag::null; }

inline
std::string tagName(const TypeTag& tag) noexcept
{
    switch (tag)
    {
        case TypeTag::object: return "Object";
        case TypeTag::array: return "Array";
        case TypeTag::string: return "String";
        case TypeTag::integer: return "Integer";
        case TypeTag::real: return "Real";
        case TypeTag::boolean: return "Boolean";
        case TypeTag::null: return "Null";
        case TypeTag::unknown: return {};
        default: return {};
    }
}

}

class Value
{
    public:
        struct Error : public std::runtime_error {
            explicit Error(const std::string& message) noexcept : runtime_error(message) {}
        };

        static Value object(const Object& v) noexcept { return Value{v}; }
        static Value array(const Array& v) noexcept { return Value{v}; }
        static Value string(const std::string& v) noexcept { return Value{v}; }
        static Value integer(int64_t v) noexcept { return Value{v}; }
        static Value real(double v) noexcept { return Value{v}; }
        static Value boolean(bool v) noexcept { return Value{v}; }
        static Value null() noexcept { return Value{Null{}}; }

        template <typename T>
        bool is() const noexcept { return m_typeTag == Impl::typeTag<T>(); }

        template <typename T>
        T get() const
        {
            if (!is<T>())
                throw Error("Type mismatch. Expected type: '" + Impl::typeName<T>() + "'. Actual type: '" + Impl::tagName(m_typeTag) + "'.");
            switch (m_typeTag)
            {
                case Impl::TypeTag::object: return m_object;
                case Impl::TypeTag::array: return m_array;
                case Impl::TypeTag::string: return m_string;
                case Impl::TypeTag::integer: return m_integer;
                case Impl::TypeTag::real: return m_real;
                case Impl::TypeTag::boolean: return m_boolean;
                case Impl::TypeTag::null: throw Error("Null value.");
                default: throw Error("Unknown value.");
            }
        }

        std::string toString(bool pretty = false, size_t indent = 0) const noexcept
        {
            switch (m_typeTag)
            {
                case Impl::TypeTag::object: return objectToString(m_object, pretty, indent);
                case Impl::TypeTag::array: return arrayToString(m_array, pretty, indent);
                case Impl::TypeTag::string: return "'" + m_string + "'";
                case Impl::TypeTag::integer: return std::to_string(m_integer);
                case Impl::TypeTag::real: return std::to_string(m_real);
                case Impl::TypeTag::boolean: return m_boolean ? "true" : "false";
                case Impl::TypeTag::null: return "null";
                default: return {};
            }
        }

    private:
        static std::string objectToString(const Object& obj, bool pretty, size_t indent) noexcept
        {
            std::string res = "{";
            bool first = true;
            for (const auto& item : obj)
            {
                if (first)
                {
                    first = false;
                }
                else
                {
                    res += ",";
                    first = false;
                }
                if (pretty)
                    res += "\n" + std::string(indent * 2, ' ');
                res += item.first + ":";
                if (pretty)
                    res += " ";
                res += item.second.toString(pretty, indent + 1);
            }
            if (pretty)
            {
                res += "\n";
                if (indent > 0)
                    res += std::string(indent - 1, ' ');
            }
            res += "}";
            return res;
        }

        static std::string arrayToString(const Array& arr, bool pretty, size_t indent) noexcept
        {
            std::string res = "[";
            if (pretty)
                res += "\n";
            bool first = true;
            for (const auto& item : arr)
            {
                if (first)
                {
                    first = false;
                }
                else
                {
                    res += ",";
                    first = false;
                }
                if (pretty)
                    res += "\n" + std::string(indent * 2, ' ');
                res += item.toString(pretty, indent + 1);
            }
            if (pretty)
            {
                res += "\n";
                if (indent > 0)
                    res += std::string(indent - 1, ' ');
            }
            res += "]";
            return res;
        }

        Value() noexcept : m_typeTag(Impl::TypeTag::unknown) {}
        explicit Value(Null) noexcept : m_typeTag(Impl::TypeTag::null) {}
        explicit Value(const Object& v) noexcept : m_typeTag(Impl::TypeTag::object), m_object(v) {}
        explicit Value(const Array& v) noexcept : m_typeTag(Impl::TypeTag::array), m_array(v) {}
        explicit Value(const std::string& v) noexcept : m_typeTag(Impl::TypeTag::string), m_string(v) {}
        explicit Value(int64_t v) noexcept : m_typeTag(Impl::TypeTag::integer), m_integer(v) {}
        explicit Value(double v) noexcept : m_typeTag(Impl::TypeTag::real), m_real(v) {}
        explicit Value(bool v) noexcept : m_typeTag(Impl::TypeTag::real), m_boolean(v) {}

        Impl::TypeTag m_typeTag;
        Object m_object;
        Array m_array;
        std::string m_string;
        int64_t m_integer;
        double m_real;
        bool m_boolean;
};

}
