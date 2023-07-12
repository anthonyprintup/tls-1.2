#pragma once

#include "../../../Crypto/Certificate.hpp"

namespace tls::handshakes {
	struct Certificate {
		std::vector<tls::Certificate> certificates {};

		[[nodiscard]] bool verifyCertificateChains(std::string_view hostname) const;
	};
}
