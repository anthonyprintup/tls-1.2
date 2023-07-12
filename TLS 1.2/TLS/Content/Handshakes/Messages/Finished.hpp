#pragma once

#include "../../../TLS Plaintext.hpp"
#include "../Handshake.hpp"

namespace tls::handshakes {
	struct Finished: TlsPlaintext, Handshake {
		Finished() = default;
		Finished(ProtocolVersion protocolVersion, SpanType handshake = {}) noexcept;

		stream::Writer build();

		SpanType iv {};
		SpanType handshake {};
	};
}
