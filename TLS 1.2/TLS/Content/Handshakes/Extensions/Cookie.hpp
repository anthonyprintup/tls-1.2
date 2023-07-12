#pragma once

#include <cstdint>
#include <cstddef>

#include "Extension.hpp"

namespace tls::handshakes {
	struct Cookie: Extension {
		std::size_t  length {};   /* 24 bit unsigned integer */  // NOLINT(clang-diagnostic-shadow-field)
		std::uint8_t data[32] {}; /* dynamically sized array of 8 bit unsigned integers */
	};
}
