#pragma once

#include "../../../TLS Plaintext.hpp"
#include "../Handshake.hpp"

namespace tls::handshakes {
	struct ClientKeyExchange: TlsPlaintext, Handshake {
		ClientKeyExchange() = default;
		explicit ClientKeyExchange(ProtocolVersion protocolVersion, SpanType publicKey) noexcept;

		stream::Writer build();
		
		SpanType publicKey {};
	};
}
