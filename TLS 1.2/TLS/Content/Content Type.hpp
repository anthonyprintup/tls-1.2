#pragma once

namespace tls {
	// 8 bit unsigned integer
	enum struct ContentType { // https://tools.ietf.org/id/draft-ietf-tls-tls13-23.html#record-layer-1
		INVALID,
		CHANGE_CIPHER_SPEC = 20,
		ALERT,
		HANDSHAKE,
		APPLICATION_DATA,
		HEARTBEAT // removed in TLS 1.2
	};
}
