#pragma once

#include "Server Name Indication.hpp"
#include "Supported Versions.hpp"
#include "Cookie.hpp"
#include "Signature Algorithms.hpp"
#include "Negotiated Groups.hpp"
#include "Key Share.hpp"
#include "Application Layer Protocol Negotiation.hpp"

#include <variant>
#include <vector>

namespace tls::handshakes {
	// Mandatory extensions (1.3): https://tools.ietf.org/id/draft-ietf-tls-tls13-23.html#mti-extensions
	// TODO: Pre-Shared Key (https://tools.ietf.org/id/draft-ietf-tls-tls13-23.html#pre-shared-key-extension)
	using ExtensionVariant = std::variant<ServerNameIndication, SupportedVersions, Cookie, SignatureAlgorithms, NegotiatedGroups, KeyShare, ApplicationLayerProtocolNegotiation>;
	using Extensions = std::vector<ExtensionVariant>;
}
