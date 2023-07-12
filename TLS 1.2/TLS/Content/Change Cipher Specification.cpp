#include "Change Cipher Specification.hpp"

using namespace tls::handshakes;

ChangeCipherSpecification::ChangeCipherSpecification(const ProtocolVersion protocolVersion) noexcept:
	TlsPlaintext {.contentType = ContentType::CHANGE_CIPHER_SPEC, .protocolVersion = protocolVersion} {}

tls::stream::Writer ChangeCipherSpecification::build() {
	stream::Writer writer {};
	writer.write<std::uint8_t>(0x01); // Must be 0x01 by standard
	
	this->length = writer.size();
	const auto recordHeader = static_cast<const TlsPlaintext>(*this).build();

	return recordHeader + writer;
}
