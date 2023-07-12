#include "Parser.hpp"

using namespace tls;

#include "../Data Stream/Reader.hpp"

#include "../TLS Plaintext.hpp"
#include "../Content/Handshakes/Handshake.hpp"
#include "../Content/Content Type.hpp"
#include "../Content/Handshakes/Handshake Type.hpp"

#include "../Configuration.hpp"

#include <fmt/format.h>

bool parser::MessageVariant::error() const noexcept {
	return std::get_if<MessageVector>(this) == nullptr;
}

void parser::parseHandshakeMessages(MessageVariant &messageVariant, const SpanType data) {
	using namespace handshakes;
	if (messageVariant.error())
		return;

	// This function expects a TlsPlaintext record type!
	stream::Reader reader {data};

	const auto contentType     = static_cast<ContentType>(reader.read<std::uint8_t>());
	const auto protocolVersion = static_cast<ProtocolVersion>(reader.read<std::uint16_t>());
	const auto messageLength   = static_cast<std::size_t>(reader.read<std::uint16_t>());

	if (constexpr auto maximumMessageLength {(2ull << 14) / 2};
		messageLength > maximumMessageLength ||
		messageLength != data.size() - TlsPlaintext::sizeInBytes) {
		messageVariant = ErrorType::MESSAGE_LENGTH_MISMATCH;
		return;
	}

	/*
	* Alerts:
	*   - messages MUST NOT be fragmented across records,
	*   - multiple messages MUST NOT be coalesced into a single TlsPlaintext record (an alert response may only contain exactly one message)
	*/
	const auto parseAlert = [](stream::Reader &streamReader) -> alerts::Alert {
		const auto alertLevel = static_cast<alerts::AlertLevel>(streamReader.read<std::uint8_t>());
		const auto alertDescription = static_cast<alerts::AlertDescription>(streamReader.read<std::uint8_t>());
		return {.level = alertLevel, .description = alertDescription};
	};
	if (contentType == ContentType::ALERT) {
		messageVariant = parseAlert(reader);
		return;
	}

	// Check for a valid content type
	if (contentType != ContentType::HANDSHAKE) {
		messageVariant = ErrorType::INVALID_CONTENT;
		return;
	}

	// Check for a valid protocol version
	if (protocolVersion != Configuration::version) {
		messageVariant = ErrorType::PROTOCOL_VERSION_MISMATCH;
		return;
	}
	
	auto &messages = messageVariant.messages();
	auto remainingHandshakeLength = static_cast<stream::DifferenceType>(messageLength);
	do {
		const auto handshakeType = static_cast<HandshakeType>(reader.read<std::uint8_t>());
		const auto handshakeLength = static_cast<stream::DifferenceType>(reader.read<stream::UnsignedInt24>());

		// TODO: add checks for minimum struct length to avoid reading data that's out of scope
		// TODO: ensure message order
		if (handshakeType == HandshakeType::SERVER_HELLO) {
			#pragma region SERVER_HELLO
			const auto serverProtocolVersion = static_cast<ProtocolVersion>(reader.read<std::uint16_t>());
			if (serverProtocolVersion != Configuration::version) {// No downgrade support!
				messageVariant = ErrorType::SERVER_PROTOCOL_VERSION_MISMATCH;
				return;
			}

			const auto randomBytes = reader.read<Configuration::randomBytesSize>();
			const auto sessionIdLength = static_cast<std::size_t>(reader.read<std::uint8_t>());
			if (sessionIdLength > Configuration::maximumSessionIdSize) {
				messageVariant = ErrorType::SESSION_ID_LENGTH_MISMATCH;
				return;
			}

			SessionId sessionId {};
			if (sessionIdLength)
				sessionId.data = reader.read(sessionIdLength);

			const auto negotiatedCipherSuite = static_cast<Cipher>(reader.read<std::uint16_t>());
			const auto negotiatedCompressionMethod = static_cast<CompressionMethod>(reader.read<std::uint8_t>());

			if (const auto remainingByteCount = handshakeLength - ServerHello::baseSizeInBytes - sessionIdLength;
				!remainingByteCount) {
				messages.emplace_back(ServerHello {
					.serverVersion = serverProtocolVersion,
					.random = {.data = randomBytes},
					.sessionId = sessionId,
					.cipher = negotiatedCipherSuite,
					.compressionMethod = negotiatedCompressionMethod});
			} else {
				// Parse the provided extensions
				const auto extensionsLength = static_cast<std::size_t>(reader.read<std::uint16_t>());
				if (const auto expectedRemainingHandshakeLength = remainingByteCount - sizeof(std::uint16_t);
					extensionsLength != expectedRemainingHandshakeLength) {
					messageVariant = ErrorType::EXTENSIONS_LENGTH_MISMATCH;
					return;
				}

				// TODO: Parse the provided extensions
				reader.advance(extensionsLength);

				messages.emplace_back(ServerHello {
					.serverVersion = serverProtocolVersion,
					.random = {.data = randomBytes},
					.sessionId = sessionId,
					.cipher = negotiatedCipherSuite,
					.compressionMethod = negotiatedCompressionMethod});
			}
			#pragma endregion
		} else if (handshakeType == HandshakeType::CERTIFICATE) {
			#pragma region CERTIFICATE
			if (!handshakeLength) { // empty certificate
				messages.emplace_back(handshakes::Certificate {});
				continue;
			}

			const auto certificateListLength = static_cast<std::size_t>(reader.read<stream::UnsignedInt24>());

			// Verify the certificate list length
			if (const auto remainingByteCount = handshakeLength - stream::UnsignedInt24::sizeInBytes;
				remainingByteCount != certificateListLength) {
				messageVariant = ErrorType::CERTIFICATE_LENGTH_MISMATCH;
				return;
			}
			
			handshakes::Certificate certificateHandshake {};
			auto remainingCertificateBytes = static_cast<stream::DifferenceType>(certificateListLength);
			do {
				const auto certificateLength = static_cast<std::size_t>(reader.read<stream::UnsignedInt24>());
				// Verify the certificate length to avoid reading random data
				if (certificateLength + stream::UnsignedInt24::sizeInBytes > static_cast<std::size_t>(remainingCertificateBytes)) {
					messageVariant = ErrorType::CERTIFICATE_LENGTH_MISMATCH;
					return;
				}

				const auto certificateData = reader.read(certificateLength);
				auto &certificate = certificateHandshake.certificates.emplace_back(certificateData);
				if (const auto successfullyParsed = certificate.parse();
					!successfullyParsed) {
					messageVariant = ErrorType::CERTIFICATE_INVALID_ASN1_DER;
					return;
				}
				
				remainingCertificateBytes -= certificateLength + stream::UnsignedInt24::sizeInBytes;
			} while (remainingCertificateBytes > 0);

			messages.emplace_back(std::move(certificateHandshake));
			#pragma endregion
		} else if (handshakeType == HandshakeType::SERVER_KEY_EXCHANGE) {
			#pragma region SERVER_KEY_EXCHANGE
			// To parse the message we need to know the negotiated cipher
			const auto serverHello = messageVariant.find<ServerHello>();
			if (!serverHello) {
				messageVariant = ErrorType::MESSAGE_ORDER_MISMATCH;
				return;
			}

			const auto keyExchangeAlgorithm = ciphers::keyExchangeAlgorithm(serverHello->cipher);
			const auto ellipticCurveType = static_cast<EllipticCurveType>(reader.read<std::uint8_t>());
			if (ellipticCurveType != EllipticCurveType::NAMED_CURVE) {
				messageVariant = ErrorType::UNSUPPORTED_CURVE_TYPE;
				return;
			}
			const auto ellipticCurve = static_cast<NamedGroup>(reader.read<std::uint16_t>());

			const auto publicKeyLength = static_cast<std::size_t>(reader.read<std::uint8_t>());
			// Verify the public key length
			constexpr auto readBytesPart1 {
				sizeof(std::uint8_t)  + // elliptic curve type
				sizeof(std::uint16_t) + // elliptic curve
				sizeof(std::uint8_t)};  // public key length
			if (const auto remainingByteCount = handshakeLength - readBytesPart1;
				remainingByteCount <= 0) {
				messageVariant = ErrorType::PUBLIC_KEY_LENGTH_MISMATCH;
				return;
			}
			const auto publicKey = reader.read(publicKeyLength);

			const auto signatureScheme = static_cast<SignatureScheme>(reader.read<std::uint16_t>());
			const auto signatureLength = static_cast<std::size_t>(reader.read<std::uint16_t>());
			// Verify the signature length
			const auto readBytesPart2 {
				readBytesPart1        + // first part
				publicKeyLength       + // public key
				sizeof(std::uint16_t) + // signature scheme
				sizeof(std::uint16_t) + // signature length
				signatureLength};       // signature
			if (const auto remainingByteCount = handshakeLength - static_cast<stream::DifferenceType>(readBytesPart2);
				remainingByteCount != 0) {
				messageVariant = ErrorType::SIGNATURE_LENGTH_MISMATCH;
				return;
			}
			const auto signature = reader.read(signatureLength);

			messages.emplace_back(ServerKeyExchange {
				.keyExchangeAlgorithm = keyExchangeAlgorithm,
				.curveType = ellipticCurveType,
				.curve = ellipticCurve,
				.publicKey = publicKey,
				.signatureScheme = signatureScheme,
				.signature = signature});
			#pragma endregion
		} else if (handshakeType == HandshakeType::CERTIFICATE_REQUEST) {
			#pragma region CERTIFICATE_REQUEST
			const auto certificateTypeCount = static_cast<std::size_t>(reader.read<std::uint8_t>());
			if (const auto remainingByteCount =
				handshakeLength -
				sizeof(std::uint8_t); // certificate type count
				remainingByteCount <= certificateTypeCount) {
				messageVariant = ErrorType::INVALID_CERTIFICATE_REQUEST;
				return;
			}

			CertificateRequest certificateRequest {};
			for (std::size_t i {}; i < certificateTypeCount; ++i)
				certificateRequest.certificateTypes.emplace_back(static_cast<ClientCertificateType>(reader.read<std::uint8_t>()));

			const auto signatureAlgorithmsLength = static_cast<std::size_t>(reader.read<std::uint16_t>());
			if (const auto remainingByteCount =
				handshakeLength      -
				sizeof(std::uint8_t) - // certificate type count
				certificateTypeCount - // certificate types
				sizeof(std::uint16_t); // signature algorithms length
				remainingByteCount <= signatureAlgorithmsLength) {
				messageVariant = ErrorType::CERTIFICATE_REQUEST_ALGORITHMS_LENGTH_MISMATCH;
				return;
			}

			for (std::size_t i {}; i < signatureAlgorithmsLength; i += sizeof(std::uint16_t)) {
				const auto hashAlgorithm      = static_cast<HashAlgorithm>(reader.read<std::uint8_t>());
				const auto signatureAlgorithm = static_cast<SignatureAlgorithm>(reader.read<std::uint8_t>());
				certificateRequest.signatureAlgorithms.emplace_back(hashAlgorithm, signatureAlgorithm);
			}

			const auto certificateAuthoritiesListLength = static_cast<std::size_t>(reader.read<std::uint16_t>());
			if (const auto remainingByteCount =
				handshakeLength           -
				sizeof(std::uint8_t)      - // certificate type count
				certificateTypeCount      - // certificate types
				sizeof(std::uint16_t)     - // signature algorithms length
				signatureAlgorithmsLength - // signature algorithms
				sizeof(std::uint16_t)     - // certificate authorities list length
				certificateAuthoritiesListLength;
				remainingByteCount != 0) {
				messageVariant = ErrorType::CERTIFICATE_REQUEST_AUTHORITIES_LENGTH_MISMATCH;
				return;
			}
			if (certificateAuthoritiesListLength) {
				auto remainingCertificateAuthoritiesBytes = static_cast<stream::DifferenceType>(certificateAuthoritiesListLength);
				do {
					const auto certificateLength = static_cast<std::size_t>(reader.read<std::uint16_t>());
					const auto certificateData = reader.read(certificateLength);
					certificateRequest.distinguishedNames.emplace_back(certificateData);

					remainingCertificateAuthoritiesBytes -= certificateLength + sizeof(std::uint16_t);
				} while (remainingCertificateAuthoritiesBytes > 0);
			}

			messages.emplace_back(std::move(certificateRequest));
			#pragma endregion
		} else if (handshakeType == HandshakeType::SERVER_HELLO_DONE) {
			#pragma region SERVER_HELLO_DONE
			// Make sure the server hello done message is the last message in the message list
			if (remainingHandshakeLength - Handshake::sizeInBytes != 0) {
				messageVariant = ErrorType::EARLY_SERVER_HELLO_DONE_MESSAGE;
				return;
			}

			messages.emplace_back(ServerHelloDone {});
			return; // End of data
			#pragma endregion
		} else {
			fmt::print(FMT_STRING("Unhandled handshake type: {:X}\n"), static_cast<std::underlying_type_t<HandshakeType>>(handshakeType));
			reader.advance(handshakeLength); // unhandled data
		}

		// Decrement the remaining length to avoid accessing out of bounds data
		remainingHandshakeLength -= handshakeLength + Handshake::sizeInBytes;
	} while (remainingHandshakeLength > 0);
}

parser::MessageVariant parser::parseHandshakeMessages(const SpanType data) {
	MessageVariant messages {};
	parseHandshakeMessages(messages, data);
	
	return messages;
}
