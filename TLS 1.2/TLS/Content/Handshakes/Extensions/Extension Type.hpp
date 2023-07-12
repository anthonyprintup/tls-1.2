// ReSharper disable IdentifierTypo
#pragma once

// Mandatory extensions: https://tools.ietf.org/id/draft-ietf-tls-tls13-23.html#mti-extensions
namespace tls::handshakes {
	/* 16 bit unsigned integer */
	enum struct ExtensionType {
		SERVER_NAME = 0x0, // Server Name Indication
		MAX_FRAGMENT_LENGTH = 0x1,
		STATUS_REQUEST = 0x5,
		SUPPORTED_GROUPS = 0xA, // Negotiated Groups
		SIGNATURE_ALGORITHMS = 0xD,
		USE_SRTP = 0xE,
		HEARTBEAT = 0xF,
		APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 0x10,
		SIGNED_CERTIFICATE_TIMESTAMP = 0x12,
		CLIENT_CERTIFICATE_TYPE = 0x13,
		SERVER_CERTIFICATE_TYPE = 0x14,
		PADDING = 0x15,
		PRE_SHARED_KEY = 0x29,
		EARLY_DATA = 0x2A,
		SUPPORTED_VERSIONS = 0x2B,
		COOKIE = 0x2C,
		PSK_KEY_EXCHANGE_MODES = 0x2D,
		CERTIFICATE_AUTHORITIES = 0x2F,
		OLD_FILTERS = 0x30,
		POST_HANDSHAKE_AUTH = 0x31,
		SIGNATURE_ALGORITHMS_CERT = 0x32,
		KEY_SHARE = 0x33
	};
}
