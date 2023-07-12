#include "Algorithms.hpp"

using namespace tls;

namespace libtomcrypt {
	#include <tomcrypt.h>
	extern int aesCipherIdentifier;
}

int rijndael::aesGcmEncrypt(
	EncryptedDataType &output,
	const SpanType data,
	const SpanType secretKey, const GcmInitializationVectorType initializationVector,
	const SpanType authenticationData) {
	output.resize(data.size() + rijndael::defaultTagLength);

	unsigned long tagLength {rijndael::defaultTagLength};
	return libtomcrypt::gcm_memory(
		libtomcrypt::aesCipherIdentifier,
		secretKey.data(), static_cast<unsigned long>(secretKey.size()),
		initializationVector.data(), static_cast<unsigned long>(initializationVector.size()),
		authenticationData.data(), static_cast<unsigned long>(authenticationData.size()),
		const_cast<unsigned char*>(data.data()), static_cast<unsigned long>(data.size()),
		output.data(),
		output.data() + data.size(), &tagLength,
		GCM_ENCRYPT);
}
int rijndael::aesGcmEncrypt(
	EncryptedDataType &output,
	const std::string_view message,
	const SpanType secretKey, const GcmInitializationVectorType initializationVector,
	const SpanType authenticationData) {
	const SpanType data {reinterpret_cast<const std::uint8_t*>(message.data()), message.length()};
	return aesGcmEncrypt(output, data, secretKey, initializationVector, authenticationData);
}

int rijndael::aesGcmDecrypt(
	DecryptedDataType &output,
	const SpanType encryptedData,
	const SpanType secretKey, const GcmInitializationVectorType initializationVector,
	const SpanType authenticationData) {
	output.resize(encryptedData.size() - rijndael::defaultTagLength);

	unsigned long tagLength {rijndael::defaultTagLength};
	return libtomcrypt::gcm_memory(
		libtomcrypt::aesCipherIdentifier,
		secretKey.data(), static_cast<unsigned long>(secretKey.size()),
		initializationVector.data(), static_cast<unsigned long>(initializationVector.size()),
		authenticationData.data(), static_cast<unsigned long>(authenticationData.size()),
		output.data(), static_cast<unsigned long>(output.size()),
		const_cast<unsigned char*>(encryptedData.data()),
		const_cast<unsigned char*>(encryptedData.data()) + encryptedData.size() - tagLength, &tagLength,
		GCM_DECRYPT);
}
int rijndael::aesGcmDecrypt(
	DecryptedDataType &output,
	const EncryptedDataType &encryptedData,
	const SpanType secretKey, const GcmInitializationVectorType initializationVector,
	const SpanType authenticationData) {
	const SpanType data {encryptedData.data(), encryptedData.size()};
	return aesGcmDecrypt(output, data, secretKey, initializationVector, authenticationData);
}
