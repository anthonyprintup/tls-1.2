#pragma once

#include <vector>
#include <string_view>

#include "Extension.hpp"

namespace tls::handshakes {
	struct ApplicationLayerProtocolNegotiation: Extension { // https://tools.ietf.org/html/rfc7301#page-3 | https://tools.ietf.org/html/rfc7301#section-6
		std::vector<std::string_view> protocols {}; // protocol name list
	};
}
