#pragma once

#include "Alert Level.hpp"
#include "Alert Description.hpp"

namespace tls::alerts {
	struct Alert { // https://tools.ietf.org/id/draft-ietf-tls-tls13-23.html#alert-messages
		AlertLevel       level {};       /* 8 bit unsigned integer */
		AlertDescription description {}; /* 8 bit unsigned integer */
	};
}
