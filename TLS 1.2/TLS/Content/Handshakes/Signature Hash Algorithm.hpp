#pragma once

#include "../../Crypto/Hash Algorithm.hpp"
#include "../../Crypto/Signature Algorithm.hpp"

namespace tls::handshakes {
	struct SignatureHashAlgorithm {
		HashAlgorithm      hashAlgorithm {};
		SignatureAlgorithm signatureAlgorithm {};
	};
}
