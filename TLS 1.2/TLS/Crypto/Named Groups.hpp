// ReSharper disable IdentifierTypo
// ReSharper disable CppInconsistentNaming
// ReSharper disable CommentTypo
#pragma once

namespace tls {
	/* 16 bit unsigned integer */
	enum struct NamedGroup { // https://tools.ietf.org/id/draft-ietf-tls-tls13-28.html
		/* Elliptic Curve Groups (ECDHE) */
		SECT163K1 = 0x1,
		SECT163R1,
		SECT163R2,

		SECT193R1,
		SECT193R2,
		SECT233K1,

		SECT233R1,
		SECT239K1,
		SECT283K1,

		SECT283R1,
		SECT409K1,
		SECT409R1,

		SECT571K1,
		SECT571R1,
		SECP160K1,

		SECP160R1,
		SECP160R2,
		SECP192K1,

		SECP192R1,
		SECP224K1,
		SECP224R1,

		SECP256K1,
		SECP256R1,
		SECP384R1,

		SECP521R1,

		X25519 = 0x1D,
		X448,

		/* Finite Field Groups (DHE) */
		FFDHE2048 = 0x100,
		FFDHE3072,
		FFDHE4096,
		FFDHE6144,
		FFDHE8192
	};
}
