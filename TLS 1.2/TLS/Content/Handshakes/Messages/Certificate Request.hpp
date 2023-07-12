#pragma once

#include "../Signature Hash Algorithm.hpp"
#include "../../../Common Types.hpp"

namespace tls::handshakes {
	/* 8 bit unsigned integer */
	enum struct ClientCertificateType {
		RSA_SIGN = 1, DSS_SIGN, RSA_FIXED_DH, DSS_FIXED_DH, RSA_EPHEMERAL_DH, DSS_EPHEMERAL_DH,
		FORTEZZA_DMS = 20,
		ECDSA_SIGN = 64, RSA_FIXED_ECDH, ECDSA_FIXED_ECDH
	};
	struct CertificateRequest { // https://tools.ietf.org/html/rfc5246#section-7.4.4
		std::vector<ClientCertificateType>  certificateTypes {};
		std::vector<SignatureHashAlgorithm> signatureAlgorithms {};
		std::vector<SpanType>               distinguishedNames {};
	};
}
