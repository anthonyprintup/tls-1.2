// ReSharper disable CppNonExplicitConvertingConstructor
#pragma once

#include "../../Array.hpp"

#include <variant>
#include <string_view>

namespace tls::asn1der {
	namespace universal {
		struct Boolean;
		struct Integer;
		struct BitString;
		struct OctetString;
		struct Null;
		struct ObjectIdentifier;
		struct Utf8String;
		struct Sequence;
		struct Set;
		struct PrintableString;
		struct Ia5String;
		struct UtcTime;
		struct GeneralizedTime;
	}
	namespace contextSpecific {
		struct ContextSpecific;
	}

	using TypeVariant = std::variant<
		universal::Boolean, universal::Integer, universal::BitString, universal::OctetString, universal::Null,
		universal::ObjectIdentifier, universal::Utf8String, universal::Sequence, universal::Set, universal::PrintableString,
		universal::Ia5String, universal::UtcTime, universal::GeneralizedTime, contextSpecific::ContextSpecific>;

	template<class T>
	struct Primitive {
		T data {};
	};
	template<>
	struct Primitive<void> {};
	struct Constructed {
		std::vector<TypeVariant> children {};
	};

	enum struct TypeClass {
		UNIVERSAL,
		APPLICATION,
		CONTEXT_SPECIFIC,
		PRIVATE
	};
	
	namespace universal {
		constexpr std::size_t maximumLength {126};

		struct Boolean: Primitive<bool> {
			static constexpr std::uint8_t number = 0x01;
			static constexpr std::size_t  expectedSize = 1; // sizeof(bool)
		};
		struct Integer: Primitive<SpanType> {
			static constexpr std::uint8_t number = 0x02;
		};
		struct BitString: Primitive<SpanType>, Constructed {
			static constexpr std::uint8_t number = 0x03;

			std::uint8_t unusedBitsCount {};
			bool parse();
		};
		struct OctetString: Primitive<std::string_view>, Constructed {
			static constexpr std::uint8_t number = 0x04;

			OctetString() = default;
			OctetString(std::string_view string) noexcept;

			bool parse();
		};
		struct Null {
			static constexpr std::uint8_t number = 0x05;
			static constexpr std::size_t  expectedSize = 0;
		};
		struct ObjectIdentifier: Primitive<SpanType> {
			static constexpr std::uint8_t number = 0x06;

			template<std::size_t Size>
			[[nodiscard]] bool operator ==(const Array<Size> &data) const noexcept {
				return this->data == data;
			}
			[[nodiscard]] bool operator ==(const ObjectIdentifier &objectIdentifier) const noexcept {
				if (this->data.size() != objectIdentifier.data.size())
					return false;
				return std::memcmp(this->data.data(), objectIdentifier.data.data(), this->data.size()) == 0;
			}
		};
		struct Utf8String: Primitive<SpanType>, Constructed {
			static constexpr std::uint8_t number = 0x0C;

			Utf8String() = default;
			Utf8String(SpanType string) noexcept;
		};
		struct Sequence: Constructed {
			static constexpr std::uint8_t number = 0x10;

			SpanType sequenceData {}, data {};
		};
		struct Set: Constructed {
			static constexpr std::uint8_t number = 0x11;
		};
		struct PrintableString: Primitive<std::string_view>, Constructed {
			static constexpr std::uint8_t number = 0x13;

			PrintableString() = default;
			PrintableString(std::string_view string) noexcept;
		};
		struct Ia5String: Primitive<std::string_view>, Constructed {
			static constexpr std::uint8_t number = 0x16;

			Ia5String() = default;
			Ia5String(std::string_view string) noexcept;
		};
		struct UtcTime {
			static constexpr std::uint8_t number      = 0x17;
			static constexpr std::size_t expectedSize = 0x0D;
			static constexpr auto expectedTimezone    = 'Z';
			static constexpr auto yearDigitsCount     = 2;

			std::tm time {};
		};
		struct GeneralizedTime {
			static constexpr std::uint8_t number      = 0x18;
			static constexpr std::size_t expectedSize = 0x0F;
			static constexpr auto expectedTimezone    = 'Z';
			static constexpr auto yearDigitsCount     = 4;

			std::tm time {};
		};
	}
	namespace contextSpecific {
		struct ContextSpecific: Constructed, Primitive<SpanType> {
			std::uint8_t number {};
			
			ContextSpecific() = default;
			ContextSpecific(SpanType data, std::uint8_t number) noexcept;
			ContextSpecific(std::uint8_t number) noexcept;
		};
	}
	namespace identifiers {
		constexpr Array<9> sha256WithRsaEncryption {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
		constexpr Array<9> sha384WithRsaEncryption {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C};
		constexpr Array<9> rsaEncryption           {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
		constexpr Array<9> sha256                  {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
		constexpr Array<9> sha384                  {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02};
		constexpr Array<9> sha512                  {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03};
		constexpr Array<9> applicationCertPolicies {0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x0A};
		constexpr Array<8> caIssuers               {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02};
		constexpr Array<8> clientAuth              {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02};
		constexpr Array<8> serverAuth              {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01};
		constexpr Array<3> countryName             {0x55, 0x04, 0x06};
		constexpr Array<3> stateOrProvinceName     {0x55, 0x04, 0x08};
		constexpr Array<3> localityName            {0x55, 0x04, 0x07};
		constexpr Array<3> organizationName        {0x55, 0x04, 0x0A};
		constexpr Array<3> organizationUnitName    {0x55, 0x04, 0x0B};
		constexpr Array<3> commonName              {0x55, 0x04, 0x03};
		constexpr Array<3> keyUsage                {0x55, 0x1D, 0x0F};
		constexpr Array<3> subjectAltName          {0x55, 0x1D, 0x11};
		constexpr Array<3> extKeyUsage             {0x55, 0x1D, 0x25};
		constexpr Array<3> authorityKeyIdentifier  {0x55, 0x1D, 0x23};
	}

	struct Name {
		std::string_view countryName {};
		std::string_view stateOrProvinceName {};
		std::string_view localityName {};
		std::string_view organizationName {};
		std::string_view organizationUnitName {};
		std::string_view commonName {};
	};
	struct PublicKey {
		universal::ObjectIdentifier encryptionIdentifier {};
		universal::Integer modulus {};
		universal::Integer exponent {};
	};
	struct CertificateSignature {
		universal::ObjectIdentifier signatureAlgorithmId {};
		universal::BitString signature {};
	};
	struct Certificate {
		using EpochTimeType = std::uint64_t;

		SpanType tbsCertificate {};

		universal::Integer version {}, serialNumber {};
		universal::ObjectIdentifier signatureAlgorithmId {};
		Name issuerName {};
		EpochTimeType notBefore {}, notAfter {};
		Name subjectName {};
		PublicKey publicKey {};
		std::vector<std::string_view> alternativeNames {};
		CertificateSignature signature {};
	};
}
