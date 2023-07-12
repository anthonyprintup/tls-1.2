#pragma once

#include "../Content/Handshakes/Messages/Server Hello.hpp"
#include "../Content/Handshakes/Messages/Certificate.hpp"
#include "../Content/Handshakes/Messages/Server Key Exchange.hpp"
#include "../Content/Handshakes/Messages/Certificate Request.hpp"
#include "../Content/Handshakes/Messages/Server Hello Done.hpp"
#include "../Content/Handshakes/Messages/Finished.hpp"

#include "../Content/Alerts/Alert.hpp"

#include "../Data Stream/Stream.hpp"

namespace tls::parser {
	/*
	* Message types are the structured in the order that they're expected to be received from the server
	*   TLS 1.3: https://tools.ietf.org/id/draft-ietf-tls-tls13-23.html#protocol-overview
	*   TLS 1.2: https://tools.ietf.org/html/rfc5246#page-36
	*/
	using MessageTypeVariant = std::variant<
		handshakes::ServerHello,        // https://tools.ietf.org/html/rfc5246#page-42
		handshakes::Certificate,        // https://tools.ietf.org/html/rfc5246#page-48
		handshakes::ServerKeyExchange,  // https://tools.ietf.org/html/rfc5246#page-52
		handshakes::CertificateRequest, // https://tools.ietf.org/html/rfc5246#section-7.4.4
		handshakes::ServerHelloDone,    // https://tools.ietf.org/html/rfc5246#page-55
		handshakes::Finished>;          // https://tools.ietf.org/html/rfc5246#page-63
	enum struct ErrorType {
		INVALID_CONTENT,
		MESSAGE_LENGTH_MISMATCH,
		MESSAGE_ORDER_MISMATCH,
		SESSION_ID_LENGTH_MISMATCH,
		EXTENSIONS_LENGTH_MISMATCH,
		CERTIFICATE_LENGTH_MISMATCH,
		CERTIFICATE_INVALID_ASN1_DER,
		CERTIFICATE_INVALID_CERTIFICATE_CHAIN,
		PUBLIC_KEY_LENGTH_MISMATCH,
		SIGNATURE_LENGTH_MISMATCH,
		INVALID_CERTIFICATE_REQUEST,
		CERTIFICATE_REQUEST_ALGORITHMS_LENGTH_MISMATCH,
		CERTIFICATE_REQUEST_AUTHORITIES_LENGTH_MISMATCH,
		UNSUPPORTED_CURVE_TYPE,
		DECODE_ERROR,
		PROTOCOL_VERSION_MISMATCH,
		SERVER_PROTOCOL_VERSION_MISMATCH,
		EARLY_SERVER_HELLO_DONE_MESSAGE,
		EARLY_FINISHED_MESSAGE,
		NO_SERVER_HELLO_MESSAGE
	};

	using MessageVector  = std::vector<MessageTypeVariant>;
	struct MessageVariant: std::variant<ErrorType, alerts::Alert, MessageVector> {
		MessageVariant() noexcept {
			this->emplace<MessageVector>();
		}
		MessageVariant(ErrorType &&error) noexcept {
			*this = std::move(error);
		}
		
		[[nodiscard]] bool error() const noexcept;

		[[nodiscard]] MessageVector &messages() {
			return std::get<MessageVector>(*this);
		}
		[[nodiscard]] const MessageVector &messages() const {
			return std::get<MessageVector>(*this);
		}

		template<class T>
		[[nodiscard]] const T *find() const noexcept {
			if (this->error())
				return {};
			for (const auto messageVector = std::get_if<MessageVector>(this);
				const auto &message : *messageVector)
				if (const auto result = std::get_if<T>(&message))
					return result;
			return {};
		}

		MessageVariant &operator =(ErrorType &&error) noexcept {
			this->emplace<ErrorType>(error);
			return *this;
		}
		MessageVariant &operator =(alerts::Alert &&alert) noexcept {
			this->emplace<alerts::Alert>(alert);
			return *this;
		}
	};

	/*
	* This function expects a TlsPlaintext record type!
	* Only a handshake content type is supported
	*/
	void parseHandshakeMessages(MessageVariant &messageVariant, SpanType data);
	MessageVariant parseHandshakeMessages(SpanType data);
}
