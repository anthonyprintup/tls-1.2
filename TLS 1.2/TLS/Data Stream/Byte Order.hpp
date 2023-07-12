#pragma once

namespace tls::stream {
	enum struct ByteOrder {
		LITTLE_ENDIAN,
		BIG_ENDIAN, // commonplace network byte order

		NETWORK_ORDER = BIG_ENDIAN
	};
}
