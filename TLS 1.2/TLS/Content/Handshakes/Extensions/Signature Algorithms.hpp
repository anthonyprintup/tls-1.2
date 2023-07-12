#pragma once

#include "Extension.hpp"
#include "../../../Crypto/Signature Scheme.hpp"

#include <vector>

namespace tls::handshakes {
	struct SignatureAlgorithms: Extension {
		std::vector<SignatureScheme> algorithms {}; // supported signature algorithms
	};
}
