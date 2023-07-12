#pragma once

namespace tls {
	/* 16 bit unsigned integer */
	enum struct ProtocolVersion { // https://tools.ietf.org/id/draft-ietf-tls-tls13-23.html#record-layer-1 | https://tlsfingerprint.io/top/versions
		VERSION_1_0 = 0x0301,
		VERSION_1_1,
		VERSION_1_2,
		VERSION_1_3,
	};
}
