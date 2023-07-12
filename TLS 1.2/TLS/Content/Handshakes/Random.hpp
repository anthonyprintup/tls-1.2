#pragma once

#include "../../Array.hpp"
#include "../../Configuration.hpp"

namespace tls::handshakes {
	/* 32 byte array of 8 bit unsigned integers */
	struct Random { // https://tools.ietf.org/id/draft-ietf-tls-tls13-23.html#key-exchange-messages-1
		Array<Configuration::randomBytesSize> data {};
	};
}
