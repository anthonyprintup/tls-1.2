#include "Hashes.hpp"

using namespace tls;

namespace libtomcrypt {
	#include <tomcrypt.h>
	extern int sha256HashIdentifier;
	extern int sha384HashIdentifier;
	extern int sha512HashIdentifier;
}

int SecureHashingAlgorithm::sha256(const std::initializer_list<SpanType> dataList, Sha256Buffer &buffer) noexcept {
	libtomcrypt::hash_state state {};
	libtomcrypt::sha256_init(&state);
	for (auto &&data : dataList)
		if (const auto error = libtomcrypt::sha256_process(&state, data.data(), static_cast<unsigned long>(data.size()));
			error != libtomcrypt::CRYPT_OK)
			return error;

	if (const auto error = libtomcrypt::sha256_done(&state, buffer.data());
		error != libtomcrypt::CRYPT_OK)
		return error;

	return libtomcrypt::CRYPT_OK;
}
int SecureHashingAlgorithm::sha384(const std::initializer_list<SpanType> dataList, Sha384Buffer &buffer) noexcept {
	libtomcrypt::hash_state state {};
	libtomcrypt::sha384_init(&state);
	for (auto &&data : dataList)
		if (const auto error = libtomcrypt::sha384_process(&state, data.data(), static_cast<unsigned long>(data.size()));
			error != libtomcrypt::CRYPT_OK)
			return error;

	if (const auto error = libtomcrypt::sha384_done(&state, buffer.data());
		error != libtomcrypt::CRYPT_OK)
		return error;

	return libtomcrypt::CRYPT_OK;
}
int SecureHashingAlgorithm::sha512(const std::initializer_list<SpanType> dataList, Sha512Buffer &buffer) noexcept {
	libtomcrypt::hash_state state {};
	libtomcrypt::sha512_init(&state);
	for (auto &&data : dataList)
		if (const auto error = libtomcrypt::sha512_process(&state, data.data(), static_cast<unsigned long>(data.size()));
			error != libtomcrypt::CRYPT_OK)
			return error;

	if (const auto error = libtomcrypt::sha512_done(&state, buffer.data());
		error != libtomcrypt::CRYPT_OK)
		return error;

	return libtomcrypt::CRYPT_OK;
}

int SecureHashingAlgorithm::hmacSha256(const SpanType key, const std::initializer_list<SpanType> dataList, Sha256Buffer &buffer) noexcept {
	libtomcrypt::hmac_state hmacState {};
	if (const auto error = libtomcrypt::hmac_init(&hmacState, libtomcrypt::sha256HashIdentifier, key.data(), static_cast<unsigned long>(key.size()));
		error != libtomcrypt::CRYPT_OK)
		return error;

	for (auto &&data : dataList)
		if (const auto error = libtomcrypt::hmac_process(&hmacState, data.data(), static_cast<unsigned long>(data.size()));
			error != libtomcrypt::CRYPT_OK)
			return error;

	auto bufferSize {static_cast<unsigned long>(buffer.size())};
	if (const auto error = libtomcrypt::hmac_done(&hmacState, buffer.data(), &bufferSize);
		error != libtomcrypt::CRYPT_OK)
		return error;

	return libtomcrypt::CRYPT_OK;
}
int SecureHashingAlgorithm::hmacSha384(const SpanType key, const std::initializer_list<SpanType> dataList, Sha384Buffer &buffer) noexcept {
	libtomcrypt::hmac_state hmacState {};
	if (const auto error = libtomcrypt::hmac_init(&hmacState, libtomcrypt::sha384HashIdentifier, key.data(), static_cast<unsigned long>(key.size()));
		error != libtomcrypt::CRYPT_OK)
		return error;

	for (auto &&data : dataList)
		if (const auto error = libtomcrypt::hmac_process(&hmacState, data.data(), static_cast<unsigned long>(data.size()));
			error != libtomcrypt::CRYPT_OK)
			return error;

	auto bufferSize {static_cast<unsigned long>(buffer.size())};
	if (const auto error = libtomcrypt::hmac_done(&hmacState, buffer.data(), &bufferSize);
		error != libtomcrypt::CRYPT_OK)
		return error;

	return libtomcrypt::CRYPT_OK;
}
int SecureHashingAlgorithm::hmacSha512(const SpanType key, const std::initializer_list<SpanType> dataList, Sha512Buffer &buffer) noexcept {
	libtomcrypt::hmac_state hmacState {};
	if (const auto error = libtomcrypt::hmac_init(&hmacState, libtomcrypt::sha512HashIdentifier, key.data(), static_cast<unsigned long>(key.size()));
		error != libtomcrypt::CRYPT_OK)
		return error;

	for (auto &&data : dataList)
		if (const auto error = libtomcrypt::hmac_process(&hmacState, data.data(), static_cast<unsigned long>(data.size()));
			error != libtomcrypt::CRYPT_OK)
			return error;

	auto bufferSize {static_cast<unsigned long>(buffer.size())};
	if (const auto error = libtomcrypt::hmac_done(&hmacState, buffer.data(), &bufferSize);
		error != libtomcrypt::CRYPT_OK)
		return error;

	return libtomcrypt::CRYPT_OK;
}
