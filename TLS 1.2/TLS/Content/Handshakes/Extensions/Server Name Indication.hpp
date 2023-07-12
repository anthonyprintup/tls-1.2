#pragma once

#include "Extension.hpp"

#include <string_view>
#include <vector>

namespace tls::handshakes {
	/*
	 * At the moment there is only one possible name type (HostName), therefore specialization isn't required
	 */
	struct ServerNameIndication: Extension { // https://tools.ietf.org/html/rfc6066#page-6
		std::vector<std::string_view> hostNames {};
	};
}
