#pragma once

#include "Protocol Version.hpp"

namespace tls::Configuration {
	constexpr auto version {ProtocolVersion::VERSION_1_2}; // TLS 1.2
	constexpr auto randomBytesSize {32ull};
	constexpr auto maximumSessionIdSize {32ull};
}
