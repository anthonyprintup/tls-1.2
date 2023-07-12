#include "Client Hello.hpp"

using namespace tls::handshakes;

#include "../Extensions/Extension Type.hpp"

ClientHello::ClientHello(const ProtocolVersion protocolVersion) noexcept:
	TlsPlaintext {.contentType = ContentType::HANDSHAKE, .protocolVersion = protocolVersion},
	Handshake {.type = HandshakeType::CLIENT_HELLO},
	clientVersion {protocolVersion} {}

tls::stream::Writer ClientHello::build() {
	stream::Writer writer {};
	writer.reserve(0x100);

	// ClientHello
	writer.write<std::uint16_t>(static_cast<std::uint16_t>(this->clientVersion));
	writer.write(this->random.data);

	// ClientHello::sessionId
	writer.write<std::uint8_t>(static_cast<std::uint8_t>(this->sessionId.data.size())); // session id length
	if (!this->sessionId.data.empty())
		writer.write(this->sessionId.data);

	// ClientHello::ciphers
	const auto cipherListSize = static_cast<std::uint16_t>(this->ciphers.size() * sizeof(std::uint16_t));
	writer.write<std::uint16_t>(cipherListSize);
	for (auto &&cipher : this->ciphers)
		writer.write<std::uint16_t>(static_cast<std::uint16_t>(cipher));

	// ClientHello::compressionMethods
	writer.write<std::uint8_t>(static_cast<std::uint8_t>(this->compressionMethods.size()));
	for (auto &&compressionMethod : this->compressionMethods)
		writer.write<std::uint8_t>(static_cast<std::uint8_t>(compressionMethod));

	// ClientHello::extensions
	const auto extensionsLengthPosition = writer.write<std::uint16_t>();
	const auto streamSizeBeforeExtensions = writer.size();
	for (const auto &extensionVariant : this->extensions) {
		if (const auto sni = std::get_if<ServerNameIndication>(&extensionVariant)) { // Server Name Indication
			writer.write<std::uint16_t>(static_cast<std::uint16_t>(ExtensionType::SERVER_NAME));

			auto extensionSize {
				sizeof(std::uint16_t) + // bytes of list entry
				sni->hostNames.size() * (
					sizeof(std::uint8_t)  + // list entry type
					sizeof(std::uint16_t)   // host name length
			)};
			for (const auto hostName : sni->hostNames)
				extensionSize += hostName.length();
			writer.write<std::uint16_t>(static_cast<std::uint16_t>(extensionSize)); // bytes of SNI extension
			writer.write<std::uint16_t>(static_cast<std::uint16_t>(extensionSize) - sizeof(std::uint16_t)); // bytes of the list entries
			for (const auto hostName : sni->hostNames) {
				writer.write<std::uint8_t>(0x00); // list entry type - always "HostName"
				writer.write<std::uint16_t>(static_cast<std::uint16_t>(hostName.length()));
				writer.write(hostName);
			}
		} else if (const auto supportedVersions = std::get_if<SupportedVersions>(&extensionVariant)) { // Supported Versions
			writer.write<std::uint16_t>(static_cast<std::uint16_t>(ExtensionType::SUPPORTED_VERSIONS));

			const auto extensionSize {
				sizeof(std::uint8_t) + // bytes of list entry
				supportedVersions->versions.size() * sizeof(std::uint16_t) // version
			};
			writer.write<std::uint16_t>(static_cast<std::uint16_t>(extensionSize)); // bytes of supported versions extension
			writer.write<std::uint8_t>(static_cast<std::uint8_t>(extensionSize) - sizeof(std::uint8_t));
			for (const auto version : supportedVersions->versions)
				writer.write<std::uint16_t>(static_cast<std::uint16_t>(version));
		} else if (const auto signatureAlgorithms = std::get_if<SignatureAlgorithms>(&extensionVariant)) { // Signature Algorithms
			writer.write<std::uint16_t>(static_cast<std::uint16_t>(ExtensionType::SIGNATURE_ALGORITHMS));

			const auto extensionSize {
				sizeof(std::uint16_t) + // bytes of list entry
				signatureAlgorithms->algorithms.size() * sizeof(std::uint16_t) // signature algorithm
			};
			writer.write<std::uint16_t>(static_cast<std::uint16_t>(extensionSize)); // bytes of signature algorithms extension
			writer.write<std::uint16_t>(static_cast<std::uint16_t>(extensionSize) - sizeof(std::uint16_t)); // bytes of list entries
			for (const auto signatureAlgorithm : signatureAlgorithms->algorithms)
				writer.write<std::uint16_t>(static_cast<std::uint16_t>(signatureAlgorithm));
		} else if (const auto negotiatedGroups = std::get_if<NegotiatedGroups>(&extensionVariant)) { // Negotiated Groups
			writer.write<std::uint16_t>(static_cast<std::uint16_t>(ExtensionType::SUPPORTED_GROUPS));

			const auto extensionSize {
				sizeof(std::uint16_t) + // bytes of list entry
				negotiatedGroups->groups.size() * sizeof(std::uint16_t) // named group
			};
			writer.write<std::uint16_t>(static_cast<std::uint16_t>(extensionSize)); // bytes of negotiated groups extension
			writer.write<std::uint16_t>(static_cast<std::uint16_t>(extensionSize) - sizeof(std::uint16_t)); // bytes of list entries
			for (const auto namedGroup : negotiatedGroups->groups)
				writer.write<std::uint16_t>(static_cast<std::uint16_t>(namedGroup));
		}
		//} else if (const auto applicationLayerProtocolNegotiation = std::get_if<ApplicationLayerProtocolNegotiation>(&extensionVariant)) { // Application Layer Protocol Negotiation
		//	writer.write<std::uint16_t>(static_cast<std::uint16_t>(ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION));

		//	auto extensionSize {sizeof(std::uint16_t) /* extension length bytes */ + sizeof(std::uint16_t) /* ALPN extension length */};
		//	for (const auto protocol : applicationLayerProtocolNegotiation->protocols)
		//		extensionSize += sizeof(std::uint8_t) /* string length */ + protocol.length() /* string */;
		//	writer.write<std::uint16_t>(static_cast<std::uint16_t>(extensionSize)); // extension length
		//	writer.write<std::uint16_t>(static_cast<std::uint16_t>(extensionSize - sizeof(std::uint16_t))); // ALPN extension length
		//	
		//	for (const auto protocol : applicationLayerProtocolNegotiation->protocols) {
		//		writer.write<std::uint8_t>(static_cast<std::uint8_t>(protocol.length()));
		//		writer.write(protocol);
		//	}
		//}
	}
	const auto streamSizeAfterExtensions = writer.size();

	const auto extensionsLength {streamSizeAfterExtensions - streamSizeBeforeExtensions};
	*reinterpret_cast<std::uint16_t*>(writer.data() + extensionsLengthPosition) = _byteswap_ushort(static_cast<std::uint16_t>(extensionsLength));

	static_cast<Handshake*>(this)->length = streamSizeAfterExtensions;
	const auto handshakeHeader = static_cast<const Handshake>(*this).build();
	
	static_cast<TlsPlaintext*>(this)->length = streamSizeAfterExtensions + handshakeHeader.size();
	const auto recordHeader = static_cast<const TlsPlaintext>(*this).build();
	
	return recordHeader + handshakeHeader + writer;
}
