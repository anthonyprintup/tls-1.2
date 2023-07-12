#pragma once

#include "../../Common Types.hpp"

namespace tls::handshakes {
	/* dynamically sized array of 8 bit unsigned integers */
	struct SessionId { // https://tools.ietf.org/id/draft-ietf-tls-tls13-23.html#key-exchange-messages-1
		SpanType data {};
		//std::size_t  length {};   /* 8 bit unsigned integer */
		//std::array<std::uint8_t, 32> data {};
	};
}
