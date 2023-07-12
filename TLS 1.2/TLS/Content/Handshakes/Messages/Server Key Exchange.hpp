#pragma once

#include "../../../Crypto/Ciphers.hpp"
#include "../../../Crypto/Named Groups.hpp"

#include "../../../Common Types.hpp"

namespace tls::handshakes {
	struct ServerKeyExchange {
		KeyExchangeAlgorithm keyExchangeAlgorithm {};
		EllipticCurveType    curveType {}; // We only support named curves
		NamedGroup           curve {};
		SpanType             publicKey {};
		SignatureScheme      signatureScheme {};
		SpanType             signature {};
	};
}
