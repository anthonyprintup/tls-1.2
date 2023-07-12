#include "Handshake.hpp"

using namespace tls::handshakes;

tls::stream::Writer Handshake::build() const {
	stream::Writer writer {};

	writer.write<std::uint8_t>(static_cast<std::uint8_t>(this->type));
	writer.write<stream::UnsignedInt24>(static_cast<decltype(stream::UnsignedInt24::value)>(this->length));

	return writer;
}
