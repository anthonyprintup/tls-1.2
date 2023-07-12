#include "Parser.hpp"

using namespace tls::asn1der;
using namespace universal;
using namespace contextSpecific;

#include <bitset>
#include <charconv>

std::uint32_t parser::size(stream::Reader &reader) {
	const auto firstByte = reader.read<std::uint8_t>();
	if (!firstByte) // special case
		return {};

	std::bitset<8> bits {firstByte};
	if (bits.test(bits.size() - 1) == false) // short form
		return firstByte;
	bits.set(bits.size() - 1, false); // long form, set last bit to 0

	const auto remainingBytes = bits.to_ulong();
	if (remainingBytes == 1)
		return reader.read<std::uint8_t>();
	if (remainingBytes == 2)
		return reader.read<std::uint16_t>();
	if (remainingBytes == 3)
		return reader.read<stream::UnsignedInt24>();
	if (remainingBytes == 4)
		return reader.read<std::uint32_t>();
	return {}; // unsupported size
}

bool parser::constructedType(Constructed *root, stream::Reader &reader, const std::size_t size) {
	const auto targetOffset = reader.offset() + size;
	while (static_cast<decltype(targetOffset)>(reader.offset()) < targetOffset)
		if (!tag(root, reader))
			return false;

	return static_cast<decltype(targetOffset)>(reader.offset()) == targetOffset;

}

bool parser::boolean(Constructed *root, stream::Reader &reader) {
	// Verify the size
	if (size(reader) != Boolean::expectedSize)
		return false;

	root->children.emplace_back(Boolean {Primitive {reader.read<std::uint8_t>() != 0}});
	return true;
}

bool parser::integer(Constructed *root, stream::Reader &reader) {
	const auto length = size(reader);
	if (!length) return false;

	root->children.emplace_back(Integer {Primitive {reader.read(length)}});
	return true;
}

bool parser::bitString(Constructed *root, stream::Reader &reader, const bool constructed) {
	const auto length = size(reader);
	if (!length) return false;

	auto &bitStringNode = std::get<BitString>(root->children.emplace_back(BitString {.unusedBitsCount = reader.read<std::uint8_t>()}));
	if (constructed)
		return constructedType(&bitStringNode, reader, length - sizeof(BitString::unusedBitsCount));
		
	bitStringNode.data = reader.read(length - sizeof(BitString::unusedBitsCount));
	return true;
}

bool parser::octetString(Constructed *root, stream::Reader &reader, const bool constructed) {
	const auto length = size(reader);
	if (!length) return false;

	if (constructed) {
		auto &parentNode = std::get<OctetString>(root->children.emplace_back(OctetString {}));
		return constructedType(&parentNode, reader, length);
	}

	const std::string_view string = {reinterpret_cast<const char*>(reader.read(length).data()), length};
	root->children.emplace_back(OctetString {string});
	return true;
}

bool parser::null(Constructed *root, stream::Reader &reader) {
	// Verify the size
	if (size(reader) != Null::expectedSize)
		return false;
	
	root->children.emplace_back(Null {});
	return true;
}

bool parser::objectIdentifier(Constructed *root, stream::Reader &reader) {
	const auto length = size(reader);
	if (!length) return false;

	root->children.emplace_back(ObjectIdentifier {Primitive {reader.read(length)}});
	return true;
}

bool parser::utf8String(Constructed *root, stream::Reader &reader, const bool constructed) {
	const auto length = size(reader);
	if (!length) return false;

	if (constructed) {
		auto &parentNode = std::get<Utf8String>(root->children.emplace_back(Utf8String {}));
		return constructedType(&parentNode, reader, length);
	}
	
	root->children.emplace_back(Utf8String {reader.read(length)});
	return true;
}

bool parser::sequence(Constructed *root, stream::Reader &reader) {
	const auto currentOffset = reader.offset();
	const auto length = size(reader);
	if (!length) return false;

	auto &parentNode = std::get<Sequence>(root->children.emplace_back(Sequence {}));

	const auto headerLength = static_cast<std::size_t>(reader.offset() - currentOffset) + 1 /* we've already read the first byte */;
	const auto data = reader.data();
	parentNode.sequenceData = data.subspan(reader.offset() - headerLength, headerLength + length);
	parentNode.data = data.subspan(reader.offset(), length);

	return constructedType(&parentNode, reader, length);
}

bool parser::set(Constructed *root, stream::Reader &reader) {
	const auto length = size(reader);
	if (!length) return false;

	auto &parentNode = std::get<Set>(root->children.emplace_back(Set {}));
	return constructedType(&parentNode, reader, length);
}

bool parser::printableString(Constructed *root, stream::Reader &reader, const bool constructed) {
	const auto length = size(reader);
	if (!length) return false;

	if (constructed) {
		auto &parentNode = std::get<PrintableString>(root->children.emplace_back(PrintableString {}));
		return constructedType(&parentNode, reader, length);
	}

	const std::string_view string {reinterpret_cast<const char*>(reader.read(length).data()), length};
	root->children.emplace_back(PrintableString {string});
	return true;
}

bool parser::ia5String(Constructed *root, stream::Reader &reader, const bool constructed) {
	const auto length = size(reader);
	if (!length) return false;

	if (constructed) {
		auto &parentNode = std::get<Ia5String>(root->children.emplace_back(Ia5String {}));
		return constructedType(&parentNode, reader, length);
	}

	const std::string_view string {reinterpret_cast<const char*>(reader.read(length).data()), length};
	root->children.emplace_back(Ia5String {string});
	return true;
}

bool parser::time(Constructed *root, stream::Reader &reader, const bool generalized) {
	// Verify the size
	const auto expectedSize = generalized ? GeneralizedTime::expectedSize : UtcTime::expectedSize;
	if (size(reader) != expectedSize)
		return false;

	const std::string_view string {reinterpret_cast<const char*>(reader.read(expectedSize).data()), expectedSize};

	// UtcTime must use the UTC timezone in DER encoding
	if (!string.ends_with(generalized ? GeneralizedTime::expectedTimezone : UtcTime::expectedTimezone))
		return false;

	const auto yearDigitsCount = generalized ? GeneralizedTime::yearDigitsCount : UtcTime::yearDigitsCount;
	
	// DER encoding UtcTime must be in format YYMMDDhhmmssZ and GeneralizedTime in format YYYYMMDDhhmmssZ
	std::tm timeData {};
	if (const auto [result, error] = std::from_chars(string.data(), string.data() + yearDigitsCount, timeData.tm_year);
		error != std::errc {} || timeData.tm_year < 0)
		return false;
	if (const auto [result, error] = std::from_chars(string.data() + yearDigitsCount, string.data() + yearDigitsCount + 2, timeData.tm_mon);
		error != std::errc {} || timeData.tm_mon < 1 || timeData.tm_mon > 12)
		return false;
	if (const auto [result, error] = std::from_chars(string.data() + yearDigitsCount + 2, string.data() + yearDigitsCount + 4, timeData.tm_mday);
		error != std::errc {} || timeData.tm_mday < 1 || timeData.tm_mday > 31)
		return false;
	if (const auto [result, error] = std::from_chars(string.data() + yearDigitsCount + 4, string.data() + yearDigitsCount + 6, timeData.tm_hour);
		error != std::errc {} || timeData.tm_hour < 0 || timeData.tm_hour > 23)
		return false;
	if (const auto [result, error] = std::from_chars(string.data() + yearDigitsCount + 6, string.data() + yearDigitsCount + 8, timeData.tm_min);
		error != std::errc {} || timeData.tm_min < 0 || timeData.tm_min > 59)
		return false;
	if (const auto [result, error] = std::from_chars(string.data() + yearDigitsCount + 8, string.data() + yearDigitsCount + 10, timeData.tm_sec);
		error != std::errc {} || timeData.tm_sec < 0 || timeData.tm_sec > 59)
		return false;

	if (!generalized && timeData.tm_year <= 50)
		timeData.tm_year += 100;
	timeData.tm_mon--;

	if (generalized)
		root->children.emplace_back(GeneralizedTime {.time = timeData});
	else
		root->children.emplace_back(UtcTime {.time = timeData});
	
	return true;
}

bool parser::contextSpecificType(Constructed *root, stream::Reader &reader, const bool constructed, const std::uint8_t number) {
	const auto length = size(reader);
	if (!length) return false;

	if (constructed) {
		auto &parentNode = std::get<ContextSpecific>(root->children.emplace_back(ContextSpecific {number}));
		return constructedType(&parentNode, reader, length);
	}
	
	root->children.emplace_back(ContextSpecific {reader.read(length), number});
	return true;
}

bool parser::tag(Constructed *root, stream::Reader &reader) {
	if (static_cast<std::size_t>(reader.offset()) == reader.size())
		return true;
		
	// ReSharper disable once CppTooWideScope
	const auto firstByte = reader.read<std::uint8_t>();
	
	const auto clazz = static_cast<TypeClass>(firstByte >> 6);
	const auto constructed = (firstByte & 0x20) != 0;
	const auto primitive = !constructed;
	const auto number = firstByte & 0x1F;

	if (number == 0x1F)
		return false; // unsupported tag form (long tag form)

	// This only implements the types used in PKCS
	if (clazz == TypeClass::UNIVERSAL) {
		if (number == Boolean::number)
			return boolean(root, reader);
		if (primitive && number == Integer::number)
			return integer(root, reader);
		if (number == BitString::number)
			return bitString(root, reader, constructed);
		if (number == OctetString::number)
			return octetString(root, reader, constructed);
		if (primitive && number == Null::number)
			return null(root, reader);
		if (primitive && number == ObjectIdentifier::number)
			return objectIdentifier(root, reader);
		if (number == Utf8String::number)
			return utf8String(root, reader, constructed);
		if (constructed && number == Sequence::number)
			return sequence(root, reader);
		if (constructed && number == Set::number)
			return set(root, reader);
		if (number == PrintableString::number)
			return printableString(root, reader, constructed);
		if (number == Ia5String::number)
			return ia5String(root, reader, constructed);
		if (number == UtcTime::number)
			return time(root, reader, false);
		if (number == GeneralizedTime::number)
			return time(root, reader, true);

		return false;
	}
	if (clazz == TypeClass::CONTEXT_SPECIFIC)
		return contextSpecificType(root, reader, constructed, static_cast<std::uint8_t>(number));
	
	return false;
}
