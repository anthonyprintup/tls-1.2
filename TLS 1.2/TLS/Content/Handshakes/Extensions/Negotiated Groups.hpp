// ReSharper disable IdentifierTypo
// ReSharper disable CppInconsistentNaming
#pragma once

#include "Extension.hpp"
#include "../../../Crypto/Named Groups.hpp"

#include <vector>

namespace tls::handshakes {
	struct NegotiatedGroups: Extension {
		std::vector<NamedGroup> groups {}; // named group list
	};
}
