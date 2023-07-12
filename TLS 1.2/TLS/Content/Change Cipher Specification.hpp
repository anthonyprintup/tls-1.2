#pragma once

#include "../TLS Plaintext.hpp"

namespace tls::handshakes {
	struct ChangeCipherSpecification: TlsPlaintext {
		ChangeCipherSpecification() = default;
		ChangeCipherSpecification(ProtocolVersion protocolVersion) noexcept;

		stream::Writer build();
	};
}
