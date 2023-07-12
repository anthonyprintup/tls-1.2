#pragma once

#include "Types.hpp"
#include "../../Data Stream/Reader.hpp"

namespace tls::asn1der::parser {
	std::uint32_t size(stream::Reader &reader);
	bool constructedType(Constructed *root, stream::Reader &reader, std::size_t size);

	bool boolean(Constructed *root, stream::Reader &reader);
	bool integer(Constructed *root, stream::Reader &reader);
	bool bitString(Constructed *root, stream::Reader &reader, bool constructed);
	bool octetString(Constructed *root, stream::Reader &reader, bool constructed);
	bool null(Constructed *root, stream::Reader &reader);
	bool objectIdentifier(Constructed *root, stream::Reader &reader);
	bool utf8String(Constructed *root, stream::Reader &reader, bool constructed);
	bool sequence(Constructed *root, stream::Reader &reader);
	bool set(Constructed *root, stream::Reader &reader);
	bool printableString(Constructed *root, stream::Reader &reader, bool constructed);
	bool ia5String(Constructed *root, stream::Reader &reader, bool constructed);
	bool time(Constructed *root, stream::Reader &reader, bool generalized);
	bool contextSpecificType(Constructed *root, stream::Reader &reader, bool constructed, std::uint8_t number);

	bool tag(Constructed *root, stream::Reader &reader);
}
