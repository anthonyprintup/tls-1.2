#pragma once

#include "../../../Protocol Version.hpp"
#include "../Random.hpp"
#include "../Session Id.hpp"
#include "../../../Crypto/Ciphers.hpp"
#include "../Compression Methods.hpp"
#include "../Extensions/Extensions.hpp"

namespace tls::handshakes {
	struct ServerHello {
		static constexpr auto baseSizeInBytes {
			sizeof(std::uint16_t) + // protocol version
			sizeof(decltype(Random::data)) + // random bytes
			sizeof(std::uint8_t) + // session id length (excluding session)
			sizeof(std::uint16_t) + // cipher suite
			sizeof(std::uint8_t)}; // compression method
		
		ProtocolVersion   serverVersion {};
		Random            random {};
		SessionId         sessionId {};
		Cipher            cipher {};
		CompressionMethod compressionMethod {};
		Extensions        extensions {};
	};
}
