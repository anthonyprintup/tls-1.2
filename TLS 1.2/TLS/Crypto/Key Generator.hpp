#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <optional>

#include "../Concepts.hpp"

namespace tls {
	namespace detail {
		constexpr std::size_t minimumKeyBits {1024};
		constexpr std::size_t maximumKeyBits {4096};
		
		template<std::size_t N>
		concept ValidKeySize = IsDivisibleBy8<N> && HigherThanOrEqual<N, minimumKeyBits> && LowerThanOrEqual<N, maximumKeyBits>;
	}
	namespace rsa {
		constexpr auto exponent {65537ull};
		
		template<std::size_t SizeInBits>
		requires detail::ValidKeySize<SizeInBits>
		struct RsaPrivateKeySizeHelper {
			static constexpr auto size = SizeInBits / CHAR_BIT * 5ull;
		};
		template<std::size_t SizeInBits>
		requires detail::ValidKeySize<SizeInBits>
		struct RsaPublicKeySizeHelper {
			static constexpr auto size = SizeInBits / CHAR_BIT * 2ull;
		};

		template<std::size_t SizeInBits>
		struct Keys {
			static constexpr auto publicKeySize  = RsaPublicKeySizeHelper<SizeInBits>::size;
			static constexpr auto privateKeySize = RsaPrivateKeySizeHelper<SizeInBits>::size;
			
			std::array<std::uint8_t, publicKeySize>  publicKey {};
			std::array<std::uint8_t, privateKeySize> privateKey {};
			std::size_t publicKeyLength {}, privateKeyLength {};
		};
	}

	int generateRsaKeys(std::uint8_t *publicKeyBytes, std::size_t &publicKeyLength, std::uint8_t *privateKeyBytes, std::size_t &privateKeyLength, std::size_t sizeInBytes) noexcept;
	
	template<template<std::size_t> class T, std::size_t N>
	requires std::is_same_v<T<N>, rsa::Keys<N>>
	std::optional<rsa::Keys<N>> generateKeys() noexcept {
		rsa::Keys<N> keys {};

		auto publicKeyLength = keys.publicKey.size(), privateKeyLength = keys.privateKey.size();
		if (const auto error = generateRsaKeys(keys.publicKey.data(), publicKeyLength, keys.privateKey.data(), privateKeyLength, N / CHAR_BIT);
			error != 0 /* libtomcrypt::CRYPT_OK */)
			return std::nullopt;

		keys.publicKeyLength = publicKeyLength;
		keys.privateKeyLength = privateKeyLength;
		return keys;
	}
}
