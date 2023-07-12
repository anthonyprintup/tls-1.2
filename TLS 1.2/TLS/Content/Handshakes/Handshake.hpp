#pragma once

#include "Handshake Type.hpp"
#include "../../Data Stream/Writer.hpp"

namespace tls::handshakes {
	struct Handshake { // https://tools.ietf.org/id/draft-ietf-tls-tls13-23.html#handshake-protocol-1
		static constexpr auto sizeInBytes {sizeof(std::uint8_t) + 3 /* 24 bit integer */};

		[[nodiscard]] stream::Writer build() const;
		
		HandshakeType type {};   /* 8  bit unsigned integer */
		std::size_t   length {}; /* 24 bit unsigned integer */
	};
}
