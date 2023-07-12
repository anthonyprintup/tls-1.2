// ReSharper disable IdentifierTypo
// ReSharper disable CommentTypo
// ReSharper disable CppInconsistentNaming
#pragma once

namespace tls {
	/* 16 bit unsigned integer */
	enum struct SignatureScheme {
		/* RSASSA-PKCS1-v1_5 algorithms */
		RSA_PKCS1_SHA256 = 0x0401,
		RSA_PKCS1_SHA384 = 0x0501,
		RSA_PKCS1_SHA512 = 0x0601,

		/* ECDSA algorithms */
		ECDSA_SECP256R1_SHA256 = 0x0403,
		ECDSA_SECP384R1_SHA384 = 0x0503,
		ECDSA_SECP521R1_SHA512 = 0x0603,

		/* RSASSA-PSS algorithms with public key OID rsaEncryption */
		RSA_PSS_RSAE_SHA256 = 0x0804,
		RSA_PSS_RSAE_SHA384 = 0x0805,
		RSA_PSS_RSAE_SHA512 = 0x0806,

		/* EdDSA algorithms */
		ED25519 = 0x0807,
		ED448   = 0x0808,

		/* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
		RSA_PSS_PSS_SHA256 = 0x0809,
		RSA_PSS_PSS_SHA384 = 0x080A,
		RSA_PSS_PSS_SHA512 = 0x080B,

		/* Legacy algorithms */
		RSA_PKCS_SHA1 = 0x0201,
		ECDSA_SHA1    = 0x0203
	};
}
