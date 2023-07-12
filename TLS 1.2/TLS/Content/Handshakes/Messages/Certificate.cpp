#include "Certificate.hpp"

using namespace tls::handshakes;

bool Certificate::verifyCertificateChains(const std::string_view hostname) const {
	for (auto iterator = this->certificates.cbegin(); iterator != this->certificates.cend(); ++iterator) {
		const auto nextEntry = iterator + 1;

		const tls::Certificate *issuer {};
		if (nextEntry != this->certificates.cend())
			issuer = &*nextEntry;
		
		if (!iterator->valid(issuer, iterator == this->certificates.cbegin() ? hostname : std::string_view {}))
			return false;
	}
	
	return true;
}
