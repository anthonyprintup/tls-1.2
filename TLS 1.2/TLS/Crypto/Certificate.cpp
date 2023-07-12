// ReSharper disable CppInitializedValueIsAlwaysRewritten
#include "Certificate.hpp"

using namespace tls;

#include "Hashes.hpp"
#include "../Parser/ASN.1 DER/Parser.hpp"
#include "../Certificate Store.hpp"

namespace libtomcrypt {
	#include <tomcrypt.h>
	
	extern int sha256HashIdentifier;
	extern int sha384HashIdentifier;
}

#include <bitset>
#include <charconv>

#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")
asn1der::Certificate::EpochTimeType utcTimeSinceEpoch() noexcept {
	LARGE_INTEGER currentTime {};
	if (NtQuerySystemTime(&currentTime) != 0 /* NT_SUCCESS */)
		return {};

	ULONG epochTime {};
	if (!RtlTimeToSecondsSince1970(&currentTime, &epochTime))
		return {};

	return epochTime;
}
asn1der::Certificate::EpochTimeType utcTimeSinceEpoch(std::tm &time) {
	return std::mktime(&time);
}

Certificate::Certificate(const SpanType certificate) noexcept:
	certificate {certificate} {}

// TODO: flatten
bool Certificate::parse() {
	this->root   = std::make_unique<decltype(this->root)::element_type>();
	this->reader = this->certificate;

	const auto successful = asn1der::parser::tag(this->root.get(), this->reader);
	if (!successful)
		this->root.reset();
	else {
		using namespace asn1der;
		constexpr std::size_t expectedRootSequenceElements {3}, minimumCertificateSignatureElements {7}, expectedIdentifiableSequenceElements {2};
		constexpr std::size_t
			tbsCertificateSequenceIndex {0},
			algorithmIdentifierIndex {tbsCertificateSequenceIndex + 1},
			signatureValueIndex {algorithmIdentifierIndex + 1};
		constexpr std::size_t
			versionNumberIndex {0},
			serialNumberIndex {versionNumberIndex + 1},
			signatureAlgorithmIdIndex {serialNumberIndex + 1},
			issuerNameIndex {signatureAlgorithmIdIndex + 1},
			validityPeriodIndex {issuerNameIndex + 1},
			subjectNameIndex {validityPeriodIndex + 1},
			subjectPublicKeyIndex {subjectNameIndex + 1};
		constexpr std::size_t
			validityPeriodFromIndex {0},
			validityPeriodToIndex {validityPeriodFromIndex + 1};
		constexpr std::size_t
			subjectPublicKeyIdentifierIndex {0},
			subjectPublicKeyBitStringIndex {subjectPublicKeyIdentifierIndex + 1};
		constexpr std::size_t
			publicKeyModulusIndex {0},
			publicKeyExponentIndex {publicKeyModulusIndex + 1};
		constexpr std::size_t
			objectIdentifierIndex {0},
			elementIndex {objectIdentifierIndex + 1};
		constexpr std::uint8_t extensions {3 /* TBSCertificate::extensions */}, subjectAltNameDnsName {2 /* GeneralName::dNSName */};

		if (this->root->children.empty())
			return false;
		
		const auto certificateSequence = std::get_if<universal::Sequence>(&this->root->children.front());
		if (certificateSequence->children.size() != expectedRootSequenceElements)
			return false;

		if (const auto tbsCertificateSequence = std::get_if<universal::Sequence>(&certificateSequence->children[tbsCertificateSequenceIndex])) {
			this->parsedCertificate.tbsCertificate = tbsCertificateSequence->sequenceData;
			if (tbsCertificateSequence->children.size() < minimumCertificateSignatureElements) return false;

			// Version Number
			if (const auto contextSpecificElement = std::get_if<contextSpecific::ContextSpecific>(&tbsCertificateSequence->children[versionNumberIndex]);
				contextSpecificElement && !contextSpecificElement->children.empty())
				if (const auto versionNumber = std::get_if<universal::Integer>(&contextSpecificElement->children.front()))
					this->parsedCertificate.version = *versionNumber;
				else return false;
			else return false;

			// Serial Number
			if (const auto serialNumberInteger = std::get_if<universal::Integer>(&tbsCertificateSequence->children[serialNumberIndex]))
				this->parsedCertificate.serialNumber = *serialNumberInteger;

			// Signature Algorithm Id
			if (const auto signatureAlgorithmIdSequence = std::get_if<universal::Sequence>(&tbsCertificateSequence->children[signatureAlgorithmIdIndex])) {
				if (signatureAlgorithmIdSequence->children.size() != expectedIdentifiableSequenceElements)
					return false;

				if (const auto objectIdentifier = std::get_if<universal::ObjectIdentifier>(&signatureAlgorithmIdSequence->children[objectIdentifierIndex]))
					this->parsedCertificate.signatureAlgorithmId = *objectIdentifier;
				else return false;
				if (const auto null = std::get_if<universal::Null>(&signatureAlgorithmIdSequence->children[elementIndex]); !null)
					return false;
			} else return false;

			// Issuer Name
			if (const auto issuerNameSequence = std::get_if<universal::Sequence>(&tbsCertificateSequence->children[issuerNameIndex]))
				// Iterate the different sets and their sequences to extract data
				for (const auto &setVariant : issuerNameSequence->children) {
					const auto set = std::get_if<universal::Set>(&setVariant);
					if (!set || set->children.empty()) return false;

					const auto sequence = std::get_if<universal::Sequence>(&set->children.front());
					if (!sequence || sequence->children.size() != expectedIdentifiableSequenceElements)
						return false;

					const auto objectIdentifier = std::get_if<universal::ObjectIdentifier>(&sequence->children[objectIdentifierIndex]);
					if (!objectIdentifier) return false;

					std::string_view value {};
					if (const auto octetString = std::get_if<universal::OctetString>(&sequence->children[elementIndex]))
						value = octetString->data;
					else if (const auto utf8String = std::get_if<universal::Utf8String>(&sequence->children[elementIndex]))
						value = {reinterpret_cast<const char*>(utf8String->data.data()), utf8String->data.size()};
					else if (const auto printableString = std::get_if<universal::PrintableString>(&sequence->children[elementIndex]))
						value = printableString->data;
					else if (const auto ia5String = std::get_if<universal::Ia5String>(&sequence->children[elementIndex]))
						value = ia5String->data;
					else return false;

					// ReSharper disable once CppTooWideScope
					auto &name = this->parsedCertificate.issuerName;
					if (*objectIdentifier == identifiers::countryName)
						name.countryName = value;
					else if (*objectIdentifier == identifiers::stateOrProvinceName)
						name.stateOrProvinceName = value;
					else if (*objectIdentifier == identifiers::localityName)
						name.localityName = value;
					else if (*objectIdentifier == identifiers::organizationName)
						name.organizationName = value;
					else if (*objectIdentifier == identifiers::organizationUnitName)
						name.organizationUnitName = value;
					else if (*objectIdentifier == identifiers::commonName)
						name.commonName = value;
					else return false; // unsupported object identifier
				}
			else return false;

			// Validity Period
			if (const auto validityPeriodSequence = std::get_if<universal::Sequence>(&tbsCertificateSequence->children[validityPeriodIndex])) {
				if (const auto validFromUtc = std::get_if<universal::UtcTime>(&validityPeriodSequence->children[validityPeriodFromIndex]))
					this->parsedCertificate.notBefore = utcTimeSinceEpoch(validFromUtc->time);
				else if (const auto validFromGeneralized = std::get_if<universal::GeneralizedTime>(&validityPeriodSequence->children[validityPeriodFromIndex]))
					this->parsedCertificate.notBefore = utcTimeSinceEpoch(validFromGeneralized->time);
				else return false;
				
				if (const auto validToUtc = std::get_if<universal::UtcTime>(&validityPeriodSequence->children[validityPeriodToIndex]))
					this->parsedCertificate.notAfter = utcTimeSinceEpoch(validToUtc->time);
				else if (const auto validToGeneralized = std::get_if<universal::GeneralizedTime>(&validityPeriodSequence->children[validityPeriodToIndex]))
					this->parsedCertificate.notAfter = utcTimeSinceEpoch(validToGeneralized->time);
				else return false;
			} else return false;
			
			// Subject Name
			if (const auto subjectNameSequence = std::get_if<universal::Sequence>(&tbsCertificateSequence->children[subjectNameIndex]))
				// Iterate the different sets and their sequences to extract data
				for (const auto &setVariant : subjectNameSequence->children) {
					const auto set = std::get_if<universal::Set>(&setVariant);
					if (!set || set->children.empty()) return false;

					const auto sequence = std::get_if<universal::Sequence>(&set->children.front());
					if (!sequence || sequence->children.size() != expectedIdentifiableSequenceElements)
						return false;

					const auto objectIdentifier = std::get_if<universal::ObjectIdentifier>(&sequence->children[objectIdentifierIndex]);
					if (!objectIdentifier) return false;

					std::string_view value {};
					if (const auto octetString = std::get_if<universal::OctetString>(&sequence->children[elementIndex]))
						value = octetString->data;
					else if (const auto utf8String = std::get_if<universal::Utf8String>(&sequence->children[elementIndex]))
						value = {reinterpret_cast<const char*>(utf8String->data.data()), utf8String->data.size()};
					else if (const auto printableString = std::get_if<universal::PrintableString>(&sequence->children[elementIndex]))
						value = printableString->data;
					else if (const auto ia5String = std::get_if<universal::Ia5String>(&sequence->children[elementIndex]))
						value = ia5String->data;
					else return false;

					// ReSharper disable once CppTooWideScope
					auto &name = this->parsedCertificate.subjectName;
					if (*objectIdentifier == identifiers::countryName)
						name.countryName = value;
					else if (*objectIdentifier == identifiers::stateOrProvinceName)
						name.stateOrProvinceName = value;
					else if (*objectIdentifier == identifiers::localityName)
						name.localityName = value;
					else if (*objectIdentifier == identifiers::organizationName)
						name.organizationName = value;
					else if (*objectIdentifier == identifiers::organizationUnitName)
						name.organizationUnitName = value;
					else if (*objectIdentifier == identifiers::commonName)
						name.commonName = value;
					else return false; // unsupported object identifier
				}
			else return false;

			// Subject Public Key
			if (const auto subjectPublicKeySequence = std::get_if<universal::Sequence>(&tbsCertificateSequence->children[subjectPublicKeyIndex])) {
				if (const auto identifierSequence = std::get_if<universal::Sequence>(&subjectPublicKeySequence->children[subjectPublicKeyIdentifierIndex])) {
					if (const auto objectIdentifier = std::get_if<universal::ObjectIdentifier>(&identifierSequence->children[objectIdentifierIndex]))
						this->parsedCertificate.publicKey.encryptionIdentifier = *objectIdentifier;
					else return false;
					if (const auto null = std::get_if<universal::Null>(&identifierSequence->children[elementIndex]); !null)
						return false;
				} else return false;

				if (const auto publicKeyBitString = std::get_if<universal::BitString>(&subjectPublicKeySequence->children[subjectPublicKeyBitStringIndex])) {
					if (publicKeyBitString->children.empty()) { // bit string was not parsed (encapsulated structures)
						if (!publicKeyBitString->parse()) return false;
						if (publicKeyBitString->children.empty()) return false;
					}

					if (const auto publicKeySequence = std::get_if<universal::Sequence>(&publicKeyBitString->children.front())) {
						if (const auto publicKeyModulusInteger = std::get_if<universal::Integer>(&publicKeySequence->children[publicKeyModulusIndex]))
							this->parsedCertificate.publicKey.modulus = *publicKeyModulusInteger;
						else return false;

						if (const auto publicKeyExponentInteger = std::get_if<universal::Integer>(&publicKeySequence->children[publicKeyExponentIndex]))
							this->parsedCertificate.publicKey.exponent = *publicKeyExponentInteger;
						else return false;
					} else return false;
				} else return false;
			} else return false;

			// Extensions
			if (tbsCertificateSequence->children.size() >= 8) {
				if (auto iterator = std::ranges::find_if(tbsCertificateSequence->children, [](const TypeVariant &variant) {
					return std::holds_alternative<contextSpecific::ContextSpecific>(variant) && std::get<contextSpecific::ContextSpecific>(variant).number == extensions;
				}); iterator != tbsCertificateSequence->children.cend()) {
					auto &extensionsContext = std::get<contextSpecific::ContextSpecific>(*iterator);
					if (extensionsContext.children.size() != 1)
						return false;

					const auto extensionsSequence = std::get_if<universal::Sequence>(&extensionsContext.children.front());
					if (!extensionsSequence) return false;

					for (auto &sequenceVariant : extensionsSequence->children) {
						const auto sequence = std::get_if<universal::Sequence>(&sequenceVariant);
						if (!sequence || sequence->children.size() != expectedIdentifiableSequenceElements)
							continue;

						const auto objectIdentifier = std::get_if<universal::ObjectIdentifier>(&sequence->children[objectIdentifierIndex]);
						if (!objectIdentifier) return false;
						if (*objectIdentifier != identifiers::subjectAltName)
							continue;

						const auto octetString = std::get_if<universal::OctetString>(&sequence->children[elementIndex]);
						if (!octetString) return false;
						if (octetString->children.empty()) { // octet string was not parsed (encapsulated structures)
							if (!octetString->parse()) return false;
							if (octetString->children.empty()) return false;
						}

						const auto subjectAltNameSequence = std::get_if<universal::Sequence>(&octetString->children.front());
						if (!subjectAltNameSequence) return false;

						for (const auto &subjectAltNameVariant : subjectAltNameSequence->children) {
							const auto subjectAltNameContext = std::get_if<contextSpecific::ContextSpecific>(&subjectAltNameVariant);
							if (!subjectAltNameContext) return false;
							if (subjectAltNameContext->number != subjectAltNameDnsName)
								continue;

							// The stored data is an IA5String
							const auto data = subjectAltNameContext->data;
							this->parsedCertificate.alternativeNames.emplace_back(reinterpret_cast<const char*>(data.data()), data.size());
						}
					}
				}
			}
		} else return false;
		if (const auto algorithmIdentifier = std::get_if<universal::Sequence>(&certificateSequence->children[algorithmIdentifierIndex])) {
			if (algorithmIdentifier->children.size() != expectedIdentifiableSequenceElements)
				return false;

			if (const auto objectIdentifier = std::get_if<universal::ObjectIdentifier>(&algorithmIdentifier->children[objectIdentifierIndex]))
				this->parsedCertificate.signature.signatureAlgorithmId = *objectIdentifier;
			else return false;
			if (const auto null = std::get_if<universal::Null>(&algorithmIdentifier->children[elementIndex]); !null)
				return false;
		} else
			return false;
		if (const auto signatureValue = std::get_if<universal::BitString>(&certificateSequence->children[signatureValueIndex]))
			this->parsedCertificate.signature.signature = *signatureValue;
		else return false;
	}
	
	return successful;
}

bool Certificate::valid(const Certificate *issuer, const std::string_view hostname) const noexcept {
	// ReSharper disable once CppTooWideScope
	const auto timeSinceEpoch = utcTimeSinceEpoch();
	if (timeSinceEpoch < this->parsedCertificate.notBefore || timeSinceEpoch > this->parsedCertificate.notAfter)
		return false;
	
	if (!hostname.empty()) { // hostname == vsblobprodscussu5shard63.blob.core.windows.net | common name == *.blob.core.windows.net
		const auto commonName = this->parsedCertificate.subjectName.commonName;
		if (commonName.empty())
			return false;

		// Wildcard limitations prevent the wildcard from being at the beginning
		bool matchedName {};
		if (const auto wildcardOffset = commonName.find_first_of('*');
			commonName.size() > 2 && wildcardOffset == 0 && commonName.find_first_of('.') == 1) {
			if (hostname.ends_with(commonName.substr(2)))
				matchedName = true;
		} else if (commonName == hostname)
			matchedName = true;

		// The common name didn't match, check for alternative subject names
		if (!matchedName)
			for (const auto alternativeName : this->parsedCertificate.alternativeNames) {
				if (const auto wildcardOffset = alternativeName.find_first_of('*');
					alternativeName.size() > 2 && wildcardOffset == 0 && alternativeName.find_first_of('.') == 1) {
					if (hostname.ends_with(alternativeName.substr(2)))
						matchedName = true;
				} else if (commonName == hostname)
					matchedName = true;
			}
		if (!matchedName)
			return false;
	}

	if (this->parsedCertificate.publicKey.encryptionIdentifier != asn1der::identifiers::rsaEncryption)
		return false; // unsupported encryption algorithm

	struct PublicRsaKey {
		libtomcrypt::rsa_key key {};

		~PublicRsaKey() {
			libtomcrypt::rsa_free(&this->key);
		}
	} rsaKey {};
	{ // Import modulus & exponent
		// ReSharper disable once CppInitializedValueIsAlwaysRewritten
		// ReSharper disable once CppInitializedValueIsAlwaysRewritten
		SpanType modulus {}, exponent {};
		if (issuer) {
			modulus  = issuer->parsedCertificate.publicKey.modulus.data;
			exponent = issuer->parsedCertificate.publicKey.exponent.data;
		} else {
			// ReSharper disable once CppTooWideScope
			const auto issuerCommonName = this->parsedCertificate.issuerName.commonName;
			if (issuerCommonName == "DigiCert Global Root G2") {
				modulus  = certificates::DigiCertGlobalRootG2::modulus;
				exponent = certificates::DigiCertGlobalRootG2::exponent;
			} else if (issuerCommonName == "Baltimore CyberTrust Root") {
				modulus  = certificates::BaltimoreCyberTrustRoot::modulus;
				exponent = certificates::BaltimoreCyberTrustRoot::exponent;
			} else
				return false; // Root issuer could not be identified
		}
		
		libtomcrypt::rsa_set_key(modulus.data(), static_cast<unsigned long>(modulus.size()), exponent.data(), static_cast<unsigned long>(exponent.size()), nullptr, 0, &rsaKey.key);
	}

	const auto signatureAlgorithmId = this->parsedCertificate.signature.signatureAlgorithmId;
	const auto signature = this->parsedCertificate.signature.signature.data;

	constexpr std::size_t maximumFingerprintSize {512}; // 4096 bits
	Array<maximumFingerprintSize> decodedCertificateFingerprint {};
	auto decodedCertificateFingerprintSize {static_cast<unsigned long>(signature.size())};

	// Verify the RSA signature
	if (const auto error = libtomcrypt::ltc_mp.rsa_me(
		signature.data(), static_cast<unsigned long>(signature.size()),
		decodedCertificateFingerprint.data(), &decodedCertificateFingerprintSize,
		libtomcrypt::PK_PUBLIC, &rsaKey.key);
		error != libtomcrypt::CRYPT_OK || signature.size() != decodedCertificateFingerprintSize)
		return false;

	// Compare the raw fingerprint with the TBS certificate's hash
	if (signatureAlgorithmId == asn1der::identifiers::sha256 &&
		decodedCertificateFingerprint == sha<256>(this->parsedCertificate.tbsCertificate))
		return true;
	if (signatureAlgorithmId == asn1der::identifiers::sha384 &&
		decodedCertificateFingerprint == sha<384>(this->parsedCertificate.tbsCertificate))
		return true;

	// At this point we can attempt to decode the certificate fingerprint again (PKCS1 v1.5)
	const auto modulusSizeInBits = libtomcrypt::ltc_mp.count_bits(rsaKey.key.N);
	auto decodedHashSequenceSize = static_cast<unsigned long>(modulusSizeInBits / 8 + (modulusSizeInBits & 7 ? 1 : 0) - 3);
	const auto decodedHashSequenceBytes = std::make_unique<UnderlyingDataType[]>(decodedHashSequenceSize);
	if (int valid {}, error = libtomcrypt::pkcs_1_v1_5_decode(
		decodedCertificateFingerprint.data(), decodedCertificateFingerprintSize,
		libtomcrypt::LTC_PKCS_1_EMSA, static_cast<unsigned long>(modulusSizeInBits),
		decodedHashSequenceBytes.get(), &decodedHashSequenceSize, &valid);
		error != libtomcrypt::CRYPT_OK || !valid)
		return false;

	// Attempt to decode the hash sequence
	asn1der::Constructed hashStructure {};
	stream::Reader hashSequenceReader {decodedHashSequenceBytes.get(), decodedHashSequenceSize};
	if (const auto successfullyParsed = asn1der::parser::tag(&hashStructure, hashSequenceReader);
		!successfullyParsed)
		return false;

	/*
	 * Children:
	 * ---------
	 * [0] Sequence
	 *   [0] Sequence
	 *     [0] Object Identifier
	 *     [1] Null
	 *   [1] Octet String
	 */
	{
		using namespace asn1der;
		using namespace universal;
		constexpr std::size_t rootSequenceIndex {0}, octetStringIndex {1}, objectIdentifierIndex {0}, valueIndex {1};
		constexpr std::size_t expectedElementsInRootSequence {2}, expectedElementsInHashSequence {2};
		
		if (hashStructure.children.empty())
			return false;

		const auto rootSequence = std::get_if<Sequence>(&hashStructure.children[rootSequenceIndex]);
		if (!rootSequence || rootSequence->children.size() != expectedElementsInRootSequence)
			return false;
		
		const auto hashSequence = std::get_if<Sequence>(&rootSequence->children.front());
		if (!hashSequence || hashSequence->children.size() != expectedElementsInHashSequence)
			return false;

		const auto signatureAlgorithmIdObjectIdentifier = std::get_if<ObjectIdentifier>(&hashSequence->children[objectIdentifierIndex]);
		if (!signatureAlgorithmIdObjectIdentifier)
			return false;
		if (const auto null = std::get_if<Null>(&hashSequence->children[valueIndex]); !null)
			return false;

		// Check for supported signature algorithms
		if (*signatureAlgorithmIdObjectIdentifier != identifiers::sha256 && *signatureAlgorithmIdObjectIdentifier != identifiers::sha384)
			return false;

		// Compare the hash
		const auto signatureOctetString = std::get_if<OctetString>(&rootSequence->children[octetStringIndex]);
		if (!signatureOctetString)
			return false;
		
		const SpanType hash {reinterpret_cast<const UnderlyingDataType*>(signatureOctetString->data.data()), signatureOctetString->data.length()};
		if (*signatureAlgorithmIdObjectIdentifier == identifiers::sha256)
			return sha<256>(this->parsedCertificate.tbsCertificate) == hash;
		if (*signatureAlgorithmIdObjectIdentifier == identifiers::sha384)
			return sha<384>(this->parsedCertificate.tbsCertificate) == hash;
		return false; // unsupported signature algorithm
	}
}
