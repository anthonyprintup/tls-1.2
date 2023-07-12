#include "Key Generator.hpp"

namespace libtomcrypt {
	#include <tomcrypt.h>
	extern int systemPrng;
}

int tls::generateRsaKeys(std::uint8_t *publicKeyBytes, std::size_t &publicKeyLength, std::uint8_t *privateKeyBytes, std::size_t &privateKeyLength, const std::size_t sizeInBytes) noexcept {
	libtomcrypt::rsa_key rsaKey {};
	if (const auto error = libtomcrypt::rsa_make_key(nullptr, libtomcrypt::systemPrng, static_cast<int>(sizeInBytes), rsa::exponent, &rsaKey);
		error != libtomcrypt::CRYPT_OK)
		return error;

	// Public key
	{
		auto size = static_cast<unsigned long>(publicKeyLength);
		if (const auto error = libtomcrypt::rsa_export(publicKeyBytes, &size, libtomcrypt::PK_PUBLIC, &rsaKey);
			error != libtomcrypt::CRYPT_OK) {
			libtomcrypt::rsa_free(&rsaKey);
			return error;
		}
		publicKeyLength = size;
	}

	// private key
	{
		auto size = static_cast<unsigned long>(privateKeyLength);
		if (const auto error = libtomcrypt::rsa_export(privateKeyBytes, &size, libtomcrypt::PK_PRIVATE, &rsaKey);
			error != libtomcrypt::CRYPT_OK) {
			libtomcrypt::rsa_free(&rsaKey);
			return error;
		}
		privateKeyLength = size;
	}

	libtomcrypt::rsa_free(&rsaKey);
	return libtomcrypt::CRYPT_OK;
}
