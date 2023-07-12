#pragma once

#include <span>

#include "../Array.hpp"

namespace tls {
	namespace SecureHashingAlgorithm {
	template<std::size_t SizeInBits>
		concept IsValidKeySize = SizeInBits == 256 || SizeInBits == 384 || SizeInBits == 512;

		template<std::size_t SizeInBits>
		requires IsValidKeySize<SizeInBits>
		using Buffer = BitArray<SizeInBits>;
		
		using Sha256Buffer = Buffer<256>;
		using Sha384Buffer = Buffer<384>;
		using Sha512Buffer = Buffer<512>;

		int sha256(std::initializer_list<SpanType> dataList, Sha256Buffer &buffer) noexcept;
		int sha384(std::initializer_list<SpanType> dataList, Sha384Buffer &buffer) noexcept;
		int sha512(std::initializer_list<SpanType> dataList, Sha512Buffer &buffer) noexcept;
		int hmacSha256(SpanType key, std::initializer_list<SpanType> dataList, Sha256Buffer &buffer) noexcept;
		int hmacSha384(SpanType key, std::initializer_list<SpanType> dataList, Sha384Buffer &buffer) noexcept;
		int hmacSha512(SpanType key, std::initializer_list<SpanType> dataList, Sha512Buffer &buffer) noexcept;

		template<class T>
		concept IsValidArgumentType = std::is_convertible_v<T, SpanType>;
	}

	template<std::size_t SizeInBits, SecureHashingAlgorithm::IsValidArgumentType... DataType>
	requires SecureHashingAlgorithm::IsValidKeySize<SizeInBits>
	SecureHashingAlgorithm::Buffer<SizeInBits> sha(const DataType... data) noexcept {
		SecureHashingAlgorithm::Buffer<SizeInBits> buffer {};
		if constexpr (SizeInBits == 256)
			if (const auto error = SecureHashingAlgorithm::sha256({data...}, buffer);
				error != 0 /* libtomcrypt::CRYPT_OK */)
				return {};
		if constexpr (SizeInBits == 384)
			if (const auto error = SecureHashingAlgorithm::sha384({data...}, buffer);
				error != 0 /* libtomcrypt::CRYPT_OK */)
				return {};
		if constexpr (SizeInBits == 512)
			if (const auto error = SecureHashingAlgorithm::sha512({data...}, buffer);
				error != 0 /* libtomcrypt::CRYPT_OK */)
				return {};
		return buffer;
	}
	
	template<std::size_t SizeInBits, SecureHashingAlgorithm::IsValidArgumentType... DataType>
	requires SecureHashingAlgorithm::IsValidKeySize<SizeInBits>
	SecureHashingAlgorithm::Buffer<SizeInBits> hmacSha(const SpanType key, const DataType... data) noexcept {
		SecureHashingAlgorithm::Buffer<SizeInBits> buffer {};
		if constexpr (SizeInBits == 256)
			if (const auto error = SecureHashingAlgorithm::hmacSha256(key, {data...}, buffer);
				error != 0 /* libtomcrypt::CRYPT_OK */)
				return {};
		if constexpr (SizeInBits == 384)
			if (const auto error = SecureHashingAlgorithm::hmacSha384(key, {data...}, buffer);
				error != 0 /* libtomcrypt::CRYPT_OK */)
				return {};
		if constexpr (SizeInBits == 512)
			if (const auto error = SecureHashingAlgorithm::hmacSha512(key, {data...}, buffer);
				error != 0 /* libtomcrypt::CRYPT_OK */)
				return {};
		return buffer;
	}
}
