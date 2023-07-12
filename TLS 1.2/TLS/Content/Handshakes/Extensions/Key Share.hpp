#pragma once

#include "Extension.hpp"
#include "../../../Crypto/Named Groups.hpp"

#include "../../../Common Types.hpp"

namespace tls::handshakes {
	struct KeyShare: Extension {
		struct Entry {
			NamedGroup group {};
			VectorType key {};
		};
		std::vector<Entry> entries {}; // client shares
	};
}
