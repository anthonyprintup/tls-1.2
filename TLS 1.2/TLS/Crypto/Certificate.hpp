#pragma once

#include "../Data Stream/Reader.hpp"
#include "../Parser/ASN.1 DER/Types.hpp"

#include <memory>
#include <string_view>

namespace tls {
	struct Certificate {
		Certificate() = default;
		Certificate(SpanType certificate) noexcept;
		
		[[nodiscard]] bool parse();
		[[nodiscard]] bool valid(const Certificate *issuer, std::string_view hostname) const noexcept;

		SpanType certificate {};
		asn1der::Certificate parsedCertificate {};
	private:
		std::unique_ptr<asn1der::universal::Sequence> root {};
		stream::Reader reader {};
	};
}
