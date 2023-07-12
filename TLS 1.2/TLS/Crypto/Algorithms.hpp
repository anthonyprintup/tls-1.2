#pragma once

#include <span>
#include <string_view>
#include <vector>

#include "../Array.hpp"

namespace tls {
	namespace rijndael {
		enum struct CipherMode {
			CBC,
			GCM
		};

		template<std::size_t SizeInBits>
		concept IsValidKeySize = SizeInBits == 128 || SizeInBits == 192 || SizeInBits == 256;
		template<std::size_t SizeInBits>
		concept IsValidHashSize = SizeInBits == 256 || SizeInBits == 384;

		constexpr std::size_t defaultTagLength {16}; // Minimum cipher block size is 16 bytes

		template<std::size_t KeySizeInBits, std::size_t HashSizeInBits, bool Mac = false>
		requires IsValidKeySize<KeySizeInBits> && IsValidHashSize<HashSizeInBits>
		struct ClientEncryptionKeys {
			constexpr static auto keySize   = BitsToBytes<KeySizeInBits>::size;
			constexpr static auto hashSize  = BitsToBytes<HashSizeInBits>::size;
			constexpr static auto ivSize = 12ull / 3ull; // Only compatible with GCM ciphers
			constexpr static auto keysSize  = keySize * 2 + ivSize * 2; // Only compatible with GCM ciphers

			Array<48>       masterSecret {};
			Array<keysSize> keys {};
			
			[[nodiscard]] decltype(auto) clientKey() const noexcept {
				return this->keys.template subarray<keySize>();
			}
			[[nodiscard]] decltype(auto) serverKey() const noexcept {
				return this->keys.template subarray<keySize>(keySize);
			}
			[[nodiscard]] decltype(auto) clientIv() const noexcept {
				return this->keys.template subarray<ivSize>(keySize * 2);
			}
			[[nodiscard]] decltype(auto) serverIv() const noexcept {
				return this->keys.template subarray<ivSize>(keySize * 2 + ivSize);
			}
		};

		using EncryptedDataType = VectorType;
		using DecryptedDataType = VectorType;

		template<class T>
		concept IsValidInputDataType = std::is_convertible_v<T, SpanType> || std::is_convertible_v<T, std::string_view>;
		template<class T>
		concept IsValidEncryptedDataType = std::is_convertible_v<T, SpanType>;
		
		template<std::size_t SizeInBits>
		requires IsValidKeySize<SizeInBits>
		using SecretKeyType = Array<BitsToBytes<SizeInBits>::size>;
		
		template<class T>
		concept IsValidSecretKeyType = std::is_same_v<T, SecretKeyType<128>> || std::is_same_v<T, SecretKeyType<192>> || std::is_same_v<T, SecretKeyType<256>>;
		
		using GcmInitializationVectorType = BitArray<96>; // The initialization vector is limited to 96 bits for efficiency in GCM mode

		int aesGcmEncrypt(EncryptedDataType &output, SpanType data, SpanType secretKey, GcmInitializationVectorType initializationVector, SpanType authenticationData);
		int aesGcmEncrypt(EncryptedDataType &output, std::string_view message, SpanType secretKey, GcmInitializationVectorType initializationVector, SpanType authenticationData);

		int aesGcmDecrypt(DecryptedDataType &output, SpanType encryptedData, SpanType secretKey, GcmInitializationVectorType initializationVector, SpanType authenticationData);
		int aesGcmDecrypt(DecryptedDataType &output, const EncryptedDataType &encryptedData, SpanType secretKey, GcmInitializationVectorType initializationVector, SpanType authenticationData);

		template<CipherMode Mode, IsValidInputDataType InputDataType, IsValidSecretKeyType KeyType>
		requires (Mode == CipherMode::GCM)
		EncryptedDataType encrypt(
			const InputDataType data,
			const KeyType secretKey,
			const GcmInitializationVectorType initializationVector,
			const SpanType authenticationData = {}) {
			EncryptedDataType buffer {};
			if (const auto error = aesGcmEncrypt(buffer, data, secretKey, initializationVector, authenticationData);
				error != 0 /* libtomcrypt::CRYPT_OK */)
				return {};
			return buffer;
		}
		template<CipherMode Mode, IsValidEncryptedDataType EncryptedDataType, IsValidSecretKeyType KeyType>
		requires (Mode == CipherMode::GCM)
		DecryptedDataType decrypt(
			const EncryptedDataType encryptedData,
			const KeyType secretKey,
			const GcmInitializationVectorType initializationVector,
			const SpanType authenticationData = {}) {
			DecryptedDataType buffer {};
			if (const auto error = aesGcmDecrypt(buffer, encryptedData, secretKey, initializationVector, authenticationData);
				error != 0 /* libtomcrypt::CRYPT_OK */)
				return {};
			return buffer;
		}
	}
	namespace aes = rijndael;
}
