#pragma once

#include "../../../TLS Plaintext.hpp"
#include "../Handshake.hpp"
#include "../Random.hpp"
#include "../Session Id.hpp"
#include "../../../Crypto/Ciphers.hpp"
#include "../Compression Methods.hpp"
#include "../Extensions/Extensions.hpp"

#include "../../../Data Stream/Writer.hpp"

namespace tls::handshakes {
	struct ClientHello: TlsPlaintext, Handshake {
		ClientHello() = default;
		explicit ClientHello(ProtocolVersion protocolVersion) noexcept;

		stream::Writer build();
		
		ProtocolVersion    clientVersion {};
		Random             random {};
		SessionId          sessionId {};          // optional (legacy) session id
		Ciphers            ciphers {};            // supported ciphers
		CompressionMethods compressionMethods {}; // supported compression methods
		Extensions         extensions {};         // supported extensions
	};
}
