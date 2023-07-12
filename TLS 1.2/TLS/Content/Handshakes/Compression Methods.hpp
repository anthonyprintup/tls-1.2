#pragma once

#include <vector>

namespace tls::handshakes {
	/* 8 bit unsigned integer */
	enum struct CompressionMethod {
		NONE = 0x0,
		DEFLATE = 0x1
	};

	/* dynamically sized array of 8 bit unsigned integers */
	using CompressionMethods = std::vector<CompressionMethod>;
}
