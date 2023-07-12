#include "Types.hpp"

using namespace tls::asn1der;
using namespace universal;
using namespace contextSpecific;

#include "Parser.hpp"

bool BitString::parse() {
	stream::Reader reader {this->data};
	return parser::constructedType(this, reader, this->data.size());
}

OctetString::OctetString(const std::string_view string) noexcept:
	Primitive {string} {}
bool OctetString::parse() {
	stream::Reader reader {reinterpret_cast<const UnderlyingDataType*>(this->data.data()), this->data.size()};
	return parser::constructedType(this, reader, this->data.size());
}

Utf8String::Utf8String(const SpanType string) noexcept:
	Primitive {string} {}

PrintableString::PrintableString(const std::string_view string) noexcept:
	Primitive {string} {}

Ia5String::Ia5String(const std::string_view string) noexcept:
	Primitive {string} {}

ContextSpecific::ContextSpecific(const SpanType data, const std::uint8_t number) noexcept:  // NOLINT(clang-diagnostic-shadow-field)
	Primitive {data}, number {number} {}

ContextSpecific::ContextSpecific(const std::uint8_t number) noexcept:
	number {number} {}
