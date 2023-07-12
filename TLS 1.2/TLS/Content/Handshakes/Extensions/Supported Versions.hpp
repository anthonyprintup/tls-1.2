#pragma once

#include "Extension.hpp"
#include "../../../Protocol Version.hpp"

#include <vector>

namespace tls::handshakes {
	struct SupportedVersions: Extension { // https://tools.ietf.org/id/draft-ietf-tls-tls13-23.html#supported-versions
		std::vector<ProtocolVersion> versions {};
	};
}
