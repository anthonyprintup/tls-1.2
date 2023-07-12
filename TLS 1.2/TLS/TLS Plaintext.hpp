#pragma once

#include "Content/Content Type.hpp"
#include "Protocol Version.hpp"

#include "Data Stream/Writer.hpp"

namespace tls {
	struct TlsPlaintext { // https://tools.ietf.org/id/draft-ietf-tls-tls13-23.html#record-layer-1
		static constexpr auto sizeInBytes {sizeof(std::uint8_t) + sizeof(std::uint16_t) + sizeof(std::uint16_t)};

		[[nodiscard]] stream::Writer build() const;
		
		ContentType     contentType {};     /* 8 bit unsigned integer  */
		ProtocolVersion protocolVersion {}; /* 16 bit unsigned integer */
		std::size_t     length {};          /* 16 bit unsigned integer */
	};
}
