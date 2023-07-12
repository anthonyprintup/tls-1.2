#include "TLS/Parser/Parser.hpp"
#include "TLS/Data Stream/Writer.hpp"

#include "TLS/Content/Handshakes/Messages/Client Key Exchange.hpp"
#include "TLS/Content/Change Cipher Specification.hpp"

#include "TLS/Crypto/Key Generator.hpp"
#include "TLS/Crypto/Certificate.hpp"
#include "TLS/Data Stream/Reader.hpp"

#pragma region WINSOCK
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma endregion

#include <fmt/format.h>
#include <random>
#include <charconv>

namespace libtomcrypt {
	#include <tomcrypt.h>

	int aesCipherIdentifier {-1};
	void registerCiphers() noexcept {
		aesCipherIdentifier = libtomcrypt::register_cipher(&libtomcrypt::aes_desc);
	}

	int sha256HashIdentifier {-1}, sha384HashIdentifier {-1}, sha512HashIdentifier {-1};
	void registerHashes() noexcept {
		sha256HashIdentifier = register_hash(&libtomcrypt::sha256_desc);
		sha384HashIdentifier = register_hash(&libtomcrypt::sha384_desc);
		sha512HashIdentifier = register_hash(&libtomcrypt::sha512_desc);
	}

	int chacha20PrngIdentifier {-1}, systemPrng {-1};
	void registerPrngs() noexcept {
		//libtomcrypt::ltc_mp = libtomcrypt::ltm_desc;
		libtomcrypt::crypt_mp_init("l");
		chacha20PrngIdentifier = register_prng(&libtomcrypt::chacha20_prng_desc);
		systemPrng = register_prng(&libtomcrypt::sprng_desc);
	}
}

#include "TLS/Crypto/Hashes.hpp"
#include "TLS/Crypto/Ciphers.hpp"
#include "TLS/Crypto/Algorithms.hpp"

template<std::size_t SizeLeft, std::size_t SizeRight>
auto operator +(const std::array<std::uint8_t, SizeLeft> &left, const std::array<std::uint8_t, SizeRight> &right) noexcept {
	std::array<std::uint8_t, SizeLeft + SizeRight> buffer {};
	std::memcpy(buffer.data(), left.data(), SizeLeft);
	std::memcpy(buffer.data() + SizeLeft, right.data(), SizeRight);

	return buffer;
}

void performTlsConnection();
int main() {  // NOLINT(bugprone-exception-escape)
	fmt::print(FMT_STRING("Hello {}\n"), "world!");

	libtomcrypt::registerCiphers();
	libtomcrypt::registerHashes();
	libtomcrypt::registerPrngs();

	/*const auto keys = tls::generateKeys<tls::rsa::Keys, 4096>();
	if (!keys) {
		fmt::print(FMT_STRING("Failed to generate RSA key pair!\n"));
		return 1;
	}
	
	{
		constexpr auto unitsPerLine {16};
		
		fmt::memory_buffer publicKeyBytes {};
		for (std::size_t i {}; i < keys->publicKeyLength; ++i) {
			const auto byte = keys->publicKey[i];
			if (i < keys->publicKeyLength)
				if ((i + 1) % (unitsPerLine * 2) == 0)
					fmt::format_to(publicKeyBytes, FMT_STRING("{:02X}\n  "), byte);
				else
					fmt::format_to(publicKeyBytes, FMT_STRING("{:02X} "), byte);
			else
				fmt::format_to(publicKeyBytes, FMT_STRING("{:02X}"), byte);
		}
		fmt::print(FMT_STRING("Public key:\n  {:.{}}\n"),
			publicKeyBytes.data(), publicKeyBytes.size());

		fmt::memory_buffer privateKeyBytes {};
		for (std::size_t i {}; i < keys->privateKeyLength; ++i) {
			const auto byte = keys->privateKey[i];
			if (i < keys->privateKeyLength)
				if ((i + 1) % (unitsPerLine * 2) == 0)
					fmt::format_to(privateKeyBytes, FMT_STRING("{:02X}\n  "), byte);
				else
					fmt::format_to(privateKeyBytes, FMT_STRING("{:02X} "), byte);
			else
				fmt::format_to(privateKeyBytes, FMT_STRING("{:02X}"), byte);
		}
		fmt::print(FMT_STRING("Private key:\n  {:.{}}\n"),
				   privateKeyBytes.data(), privateKeyBytes.size());
	}*/
	
	//performTlsConnection();
	#pragma region WINSOCK
	// WSA Startup
	WSADATA wsaData {};
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	#pragma endregion
	
	performTlsConnection();

	#pragma region WINSOCK
	WSACleanup();
	#pragma endregion

	//performTlsConnection();
}

#pragma region Socket
//constexpr std::string_view hostname {"vsblobprodscussu5shard23.blob.core.windows.net"}, portNumber {"443"};
//constexpr std::string_view hostname {"127.0.0.1"}, portNumber {"2000"};
struct Socket {
	Socket() = default;
	Socket(const std::string_view hostname, const std::string_view portNumber) {
		this->connect(hostname, portNumber);
	}
	Socket(const Socket&) = delete;
	Socket(Socket&&)      = delete;
	~Socket() {
		if (this->connectedSocket != INVALID_SOCKET)
			closesocket(this->connectedSocket);
	}

	auto operator =(const Socket&) = delete;
	auto operator =(Socket&&)      = delete;

	bool connect(const std::string_view hostname, const std::string_view portNumber) {
		if (this->connectedSocket != INVALID_SOCKET)
			closesocket(this->connectedSocket);
		
		addrinfo hints {
			.ai_family   = AF_INET,
			.ai_socktype = SOCK_STREAM,
			.ai_protocol = IPPROTO_TCP};
		addrinfo *addressInformationResult {};
		const std::string hostnameBuffer {hostname};
		if (const auto error = getaddrinfo(hostnameBuffer.c_str(), portNumber.data(), &hints, &addressInformationResult)) {
			fmt::print(FMT_STRING("Error produced when calling getaddrinfo: {}\n"), error);
			return false;
		}

		for (auto addressInformation = addressInformationResult; addressInformation; addressInformation = addressInformation->ai_next) {
			const auto temporarySocket = socket(addressInformation->ai_family, SOCK_STREAM, addressInformation->ai_protocol);
			if (temporarySocket == INVALID_SOCKET) {
				fmt::print(FMT_STRING("Failed to create a valid socket: {}\n"), WSAGetLastError());
				break;
			}

			if (::connect(temporarySocket, addressInformation->ai_addr, static_cast<int>(addressInformation->ai_addrlen)) == SOCKET_ERROR) {
				closesocket(temporarySocket);
				continue;
			}

			this->connectedSocket = temporarySocket;
			break;
		}
		freeaddrinfo(addressInformationResult);
		return this->connectedSocket != INVALID_SOCKET;
	}

	void close() noexcept {
		if (this->connectedSocket != INVALID_SOCKET) {
			closesocket(this->connectedSocket);
			this->connectedSocket = INVALID_SOCKET;
		}
	}

	bool send(const void *buffer, const std::size_t length, const int flags = 0) const {
		if (const auto error = ::send(this->connectedSocket, static_cast<const char*>(buffer), static_cast<int>(length), flags);
			error == SOCKET_ERROR) {
			fmt::print(FMT_STRING("Failed to send data: {}\n"), WSAGetLastError());
			return false;
		}
		return true;
	}
	
	int receive(void *buffer, const std::size_t size, const int flags = 0) const {
		auto remainingBytes = size;
		std::size_t offset {};
		while (true) {
			const auto receivedBytes = recv(this->connectedSocket, static_cast<char*>(buffer) + offset, static_cast<int>(remainingBytes), flags);
			if (receivedBytes == SOCKET_ERROR || !receivedBytes) {
				fmt::print(FMT_STRING("Failed to receive data: {}\n"), WSAGetLastError());
				return SOCKET_ERROR;
			}
			
			remainingBytes -= receivedBytes;
			offset += receivedBytes;
			if (!remainingBytes)
				break;
		}
		return static_cast<int>(size);
	}
	[[nodiscard]] tls::VectorType receive(const int flags = 0) const {
		tls::VectorType response {};
		
		std::array<char, 0x1000> buffer {};
		while (true) {
			if (const auto receivedBytes = this->receive(buffer.data(), buffer.size(), flags);
				receivedBytes > 0)
				response.insert(response.cend(), buffer.cbegin(), buffer.cbegin() + receivedBytes);
			else if (receivedBytes == SOCKET_ERROR) {
				fmt::print(FMT_STRING("Failed to receive data: {}\n"), WSAGetLastError());
				return {};
			}
			else break;
		}
		return response;
	}

	explicit operator bool() const noexcept {
		return this->connectedSocket != INVALID_SOCKET;
	}
private:
	SOCKET connectedSocket {INVALID_SOCKET};
};
#pragma endregion

#include "TLS/Content/Handshakes/Messages/Client Hello.hpp"

namespace tls {
	namespace client {
		template<std::size_t Bytes>
		Array<Bytes> randomBytes() {
			std::independent_bits_engine<std::default_random_engine, CHAR_BIT, std::uint32_t> randomBytesEngine {std::random_device {}()};
			Array<Bytes> entropy {};
			std::ranges::generate(entropy, std::ref(randomBytesEngine));

			return entropy;
		}

		using MasterSecretBuffer = Array<48>;
		using RandomBuffer       = Array<32>;
		namespace secp256r1 {
			using PreMasterSecretBuffer = BitArray<256>; // Specific to the curve's prime size (256)
			
			void generateKeys(const MutableSpanType secretKey, const MutableSpanType publicKey) {
				const auto entropy = randomBytes<64>();

				libtomcrypt::prng_state prngState {};
				libtomcrypt::chacha20_prng_start(&prngState);
				libtomcrypt::chacha20_prng_add_entropy(entropy.data(), static_cast<unsigned long>(entropy.size()), &prngState);
				libtomcrypt::chacha20_prng_ready(&prngState);

				libtomcrypt::ecc_key key {};
				libtomcrypt::ecc_make_key(&prngState, libtomcrypt::chacha20PrngIdentifier, static_cast<int>(secretKey.size()), &key);
				libtomcrypt::chacha20_prng_done(&prngState);

				auto privateKeyOutputLength = static_cast<unsigned long>(secretKey.size()), publicKeyOutputLength = static_cast<unsigned long>(publicKey.size());
				libtomcrypt::ecc_get_key(secretKey.data(), &privateKeyOutputLength, libtomcrypt::PK_PRIVATE, &key);
				libtomcrypt::ecc_get_key(publicKey.data(), &publicKeyOutputLength, libtomcrypt::PK_PUBLIC, &key);
				libtomcrypt::ecc_free(&key);
			}
			PreMasterSecretBuffer generatePreMasterSecret(const SpanType secretKey, const SpanType serverPublicKey) noexcept {
				PreMasterSecretBuffer buffer {};

				libtomcrypt::ecc_key privateKey {}, publicKey {};
				const libtomcrypt::ltc_ecc_curve *curve {};
				libtomcrypt::ecc_find_curve("SECP256R1", &curve);
				libtomcrypt::ecc_set_curve(curve, &privateKey);
				libtomcrypt::ecc_set_curve(curve, &publicKey);
				libtomcrypt::ecc_set_key(secretKey.data(), static_cast<unsigned long>(secretKey.size()), libtomcrypt::PK_PRIVATE, &privateKey);
				libtomcrypt::ecc_set_key(serverPublicKey.data(), static_cast<unsigned long>(serverPublicKey.size()), libtomcrypt::PK_PUBLIC, &publicKey);

				auto preMasterSecretSize = static_cast<unsigned long>(buffer.size());
				libtomcrypt::ecc_shared_secret(&privateKey, &publicKey, buffer.data(), &preMasterSecretSize);

				libtomcrypt::ecc_free(&privateKey);
				libtomcrypt::ecc_free(&publicKey);
				
				return buffer;
			}
		}
		namespace sha {
			template<std::size_t HmacHashSizeInBits>
			MasterSecretBuffer generateMasterSecret(const secp256r1::PreMasterSecretBuffer &preMasterSecret, const RandomBuffer &clientRandom, const RandomBuffer &serverRandom) noexcept {
				constexpr std::array<std::uint8_t, 13> masterSecretSeed {'m', 'a', 's', 't', 'e', 'r', ' ', 's', 'e', 'c', 'r', 'e', 't'};
				const auto seed = masterSecretSeed + clientRandom + serverRandom;

				const auto a1 = tls::hmacSha<HmacHashSizeInBits>(preMasterSecret, seed);
				const auto p1 = tls::hmacSha<HmacHashSizeInBits>(preMasterSecret, a1 + seed);

				const auto a2 = tls::hmacSha<HmacHashSizeInBits>(preMasterSecret, a1);
				const auto p2 = tls::hmacSha<HmacHashSizeInBits>(preMasterSecret, a2 + seed);

				return p1 + p2;
			}
			template<std::size_t HmacHashSizeInBits>
			auto generateKeys(const MasterSecretBuffer &masterSecret, const RandomBuffer &clientRandom, const RandomBuffer &serverRandom) noexcept {
				constexpr std::array<std::uint8_t, 13> keyExpansionArray {'k', 'e', 'y', ' ', 'e', 'x', 'p', 'a', 'n', 's', 'i', 'o', 'n'};
				const auto seed = keyExpansionArray + serverRandom + clientRandom;

				const auto a1 = tls::hmacSha<HmacHashSizeInBits>(masterSecret, seed);
				const auto a2 = tls::hmacSha<HmacHashSizeInBits>(masterSecret, a1);

				const auto p1 = tls::hmacSha<HmacHashSizeInBits>(masterSecret, a1 + seed);
				const auto p2 = tls::hmacSha<HmacHashSizeInBits>(masterSecret, a2 + seed);

				return p1 + p2;
			}
		}
		
		template<std::size_t KeySizeInBits, std::size_t HashSizeInBits, std::size_t CurveSecretKeySizeInBits, std::size_t CurvePublicKeySizeInBits>
		struct CipherData {
			static constexpr auto keySizeInBits  {KeySizeInBits};
			static constexpr auto hashSizeInBits {HashSizeInBits};
			using HashBuffer = BitArray<HashSizeInBits>;
			
			BitArray<CurveSecretKeySizeInBits> secretKey {};
			BitArray<CurvePublicKeySizeInBits> clientPublicKey {}, serverPublicKey {};
			aes::ClientEncryptionKeys<KeySizeInBits, HashSizeInBits> keys {};

			void generateKeys() {
				secp256r1::generateKeys(this->secretKey, this->clientPublicKey);
			}
			void expandKeys(const RandomBuffer &clientRandom, const RandomBuffer &serverRandom) noexcept {
				const auto preMasterSecret = secp256r1::generatePreMasterSecret(this->secretKey, this->serverPublicKey);
				const auto masterSecret = sha::generateMasterSecret<hashSizeInBits>(preMasterSecret, clientRandom, serverRandom);
				const auto generatedKeys = sha::generateKeys<hashSizeInBits>(masterSecret, clientRandom, serverRandom);

				this->keys.masterSecret = masterSecret;
				this->keys.keys = generatedKeys;
			}
			[[nodiscard]] aes::EncryptedDataType encrypt(const SpanType data, const aes::GcmInitializationVectorType &initializationVector, const SpanType authenticationData) const {
				return aes::encrypt<rijndael::CipherMode::GCM>(data, static_cast<aes::SecretKeyType<keySizeInBits>>(this->keys.clientKey()), initializationVector, authenticationData);
			}
			[[nodiscard]] aes::DecryptedDataType decrypt(const SpanType data, const aes::GcmInitializationVectorType &initializationVector, const SpanType authenticationData) const {
				return aes::decrypt<rijndael::CipherMode::GCM>(data, static_cast<aes::SecretKeyType<keySizeInBits>>(this->keys.serverKey()), initializationVector, authenticationData);
			}
		};

		using Aes128Sha256Secp256R1 = CipherData<128, 256, 256, 520>;
		using Aes256Sha384Secp256R1 = CipherData<256, 384, 256, 520>;
		using CipherDataVariant = std::variant<Aes128Sha256Secp256R1, Aes256Sha384Secp256R1>;
		
		struct Tls12ProtocolHandler {
			// ReSharper disable once CppNonExplicitConvertingConstructor
			Tls12ProtocolHandler(Socket &socket, const ProtocolVersion protocolVersion) noexcept:
				socket {socket}, _version {protocolVersion},
				clientRandom {randomBytes<32>()} {}

			template<class T>
			requires std::is_same_v<T, Aes128Sha256Secp256R1>
			void add() {
				this->cipherData.emplace_back(Aes128Sha256Secp256R1 {});
			}
			template<class T>
			requires std::is_same_v<T, Aes256Sha384Secp256R1>
			void add() {
				this->cipherData.emplace_back(Aes256Sha384Secp256R1 {});
			}
			
			[[nodiscard]] bool performHandshake(const std::string_view hostname) {
				using namespace handshakes;
				const auto clientHelloStream = this->sendClientHello(hostname);
				if (!clientHelloStream)
					return false;

				if (const auto messageVariant = this->parseHandshakeMessages(clientHelloStream.value(), hostname); messageVariant.error())
					return false;

				return this->sendClientKeyExchange() && this->sendCipherChangeSpec() && this->sendFinished() && this->receiveServerFinished();
			}

			[[nodiscard]] bool send(const SpanType data) {
				stream::Writer writer {};

				const auto encryptedData = this->encrypt(data, ContentType::APPLICATION_DATA);
				
				writer.write<std::uint8_t>(static_cast<std::uint8_t>(ContentType::APPLICATION_DATA));
				writer.write<std::uint16_t>(static_cast<std::uint16_t>(this->version()));
				writer.write<std::uint16_t>(static_cast<std::uint16_t>(encryptedData.size()));
				writer.write(encryptedData);

				if (!this->socket.send(writer.data(), writer.size()))
					return false;
				++this->clientSequenceNumber;
				return true;
			}
			[[nodiscard]] aes::DecryptedDataType receive() {
				const auto response = this->receiveRecord();
				if (response.empty())
					return {};

				stream::Reader messageReader {response};
				messageReader.advance(TlsPlaintext::sizeInBytes);
				const auto iv = messageReader.read<8>();
				const auto encryptedServerData = messageReader.read(response.size() - TlsPlaintext::sizeInBytes - sizeof(iv));

				auto decryptedServerData = this->decrypt(encryptedServerData, iv, ContentType::APPLICATION_DATA);
				++this->serverSequenceNumber;
				return decryptedServerData;
			}
			
			[[nodiscard]] ProtocolVersion version() const noexcept {
				return this->_version;
			}
		private:
			[[nodiscard]] VectorType receiveRecord() const {
				VectorType response {};
				response.resize(TlsPlaintext::sizeInBytes);

				this->socket.receive(response.data(), TlsPlaintext::sizeInBytes);

				stream::Reader reader {response};
				reader.advance(TlsPlaintext::sizeInBytes - sizeof(std::uint16_t));
				const auto remainingPacketSize = static_cast<std::size_t>(reader.read<std::uint16_t>());

				response.resize(TlsPlaintext::sizeInBytes + remainingPacketSize);
				socket.receive(response.data() + TlsPlaintext::sizeInBytes, remainingPacketSize);
				return response;
			}
			void hashHandshake(const SpanType data) noexcept {
				if (this->negotiatedCipher == Cipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
					libtomcrypt::sha384_process(&this->hashState, data.data(), static_cast<unsigned long>(data.size()));
				else if (this->negotiatedCipher == Cipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
					libtomcrypt::sha256_process(&this->hashState, data.data(), static_cast<unsigned long>(data.size()));
			}
			Array<12> generateVerifyData(const bool local) {
				constexpr std::array<std::uint8_t, 15> clientFinished {'c', 'l', 'i', 'e', 'n', 't', ' ', 'f', 'i', 'n', 'i', 's', 'h', 'e', 'd'};
				constexpr std::array<std::uint8_t, 15> serverFinished {'s', 'e', 'r', 'v', 'e', 'r', ' ', 'f', 'i', 'n', 'i', 's', 'h', 'e', 'd'};
				
				const auto previousHashState = this->hashState;

				const auto &selectedCipherVariant = this->cipherData.front();
				if (const auto aes128Sha256 = std::get_if<Aes128Sha256Secp256R1>(&selectedCipherVariant); aes128Sha256 != nullptr) {
					Array<32> hashedMessages {};
					libtomcrypt::sha256_done(&this->hashState, hashedMessages.data());
					if (local)
						this->hashState = previousHashState;

					const auto seed = (local ? clientFinished : serverFinished) + hashedMessages;
					const auto a1 = tls::hmacSha<256>(aes128Sha256->keys.masterSecret, seed);
					const auto p1 = tls::hmacSha<256>(aes128Sha256->keys.masterSecret, a1 + seed);

					return p1.subarray<12>();
				}
				if (const auto aes256Sha384 = std::get_if<Aes256Sha384Secp256R1>(&selectedCipherVariant); aes256Sha384 != nullptr) {
					Array<48> hashedMessages {};
					libtomcrypt::sha384_done(&this->hashState, hashedMessages.data());
					if (local)
						this->hashState = previousHashState;

					const auto seed = (local ? clientFinished : serverFinished) + hashedMessages;
					const auto a1 = tls::hmacSha<384>(aes256Sha384->keys.masterSecret, seed);
					const auto p1 = tls::hmacSha<384>(aes256Sha384->keys.masterSecret, a1 + seed);

					return p1.subarray<12>();
				}
				return {};
			}
			
			[[nodiscard]] std::optional<stream::Writer> sendClientHello(const std::string_view hostname) const {
				using namespace handshakes;
				ClientHello clientHello {this->version()};
				{
					// Random data
					clientHello.random.data = this->clientRandom;

					// Ciphers
					for (const auto &variant : this->cipherData)
						if (std::get_if<Aes256Sha384Secp256R1>(&variant))
							clientHello.ciphers.emplace_back(Cipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
						else if (std::get_if<Aes128Sha256Secp256R1>(&variant))
							clientHello.ciphers.emplace_back(Cipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);

					// Compression methods
					clientHello.compressionMethods.emplace_back(CompressionMethod::NONE);

					// extensions
					clientHello.extensions.emplace_back(ServerNameIndication {.hostNames = {hostname}});
					clientHello.extensions.emplace_back(SupportedVersions {.versions = {this->version()}});

					clientHello.extensions.emplace_back(SignatureAlgorithms {.algorithms = {
						SignatureScheme::ECDSA_SECP256R1_SHA256,
						SignatureScheme::ECDSA_SECP384R1_SHA384,
						SignatureScheme::ECDSA_SECP521R1_SHA512,
						SignatureScheme::RSA_PSS_RSAE_SHA256,
						SignatureScheme::RSA_PSS_RSAE_SHA384,
						SignatureScheme::RSA_PSS_RSAE_SHA512,
						SignatureScheme::RSA_PKCS1_SHA256,
						SignatureScheme::RSA_PKCS1_SHA384,
						SignatureScheme::RSA_PKCS1_SHA512,
						SignatureScheme::ECDSA_SHA1,
						SignatureScheme::RSA_PKCS_SHA1}});
					clientHello.extensions.emplace_back(NegotiatedGroups {.groups = {NamedGroup::SECP256R1}});
					//clientHello.extensions.emplace_back(ApplicationLayerProtocolNegotiation {.protocols = {"http/1.1"}});
				}
				auto clientHelloStream = clientHello.build();
				if (!this->socket.send(clientHelloStream.data(), clientHelloStream.size()))
					return std::nullopt;
				
				return clientHelloStream;  // NOLINT(clang-diagnostic-return-std-move-in-c++11)
			}
			[[nodiscard]] parser::MessageVariant parseHandshakeMessages(const SpanType clientHelloStream, const std::string_view hostname) {
				using namespace handshakes;
				
				parser::MessageVariant messages {};
				auto serverHelloReceived {false}, certificatesReceived {false}, serverKeyExchangeReceived {false};
				do {
					const auto response = this->receiveRecord();

					parser::parseHandshakeMessages(messages, response);
					if (messages.error())
						return messages;

					if (!serverHelloReceived) {
						const auto serverHello = messages.find<ServerHello>();
						if (!serverHello)
							return parser::ErrorType::NO_SERVER_HELLO_MESSAGE;

						this->negotiatedCipher = serverHello->cipher;
						this->serverRandom = serverHello->random.data;
						if (serverHello->cipher == Cipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
							libtomcrypt::sha384_init(&this->hashState);
						else if (serverHello->cipher == Cipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
							libtomcrypt::sha256_init(&this->hashState);

						// Hash ClientHello
						this->hashHandshake(clientHelloStream.subspan(TlsPlaintext::sizeInBytes));
						serverHelloReceived = true;
					}
					if (const auto handshakeType = static_cast<HandshakeType>(stream::Reader {response}.advance(TlsPlaintext::sizeInBytes).read<std::uint8_t>());
						handshakeType != HandshakeType::HELLO_REQUEST && handshakeType != HandshakeType::HELLO_VERIFY_REQUEST)
						this->hashHandshake(static_cast<SpanType>(response).subspan(TlsPlaintext::sizeInBytes));

					if (!certificatesReceived) {
						const auto serverCertificates = messages.find<handshakes::Certificate>();
						if (!serverCertificates)
							continue;

						if (!serverCertificates->verifyCertificateChains(hostname))
							return parser::ErrorType::CERTIFICATE_INVALID_CERTIFICATE_CHAIN;
						
						certificatesReceived = true;
					}
					if (!serverKeyExchangeReceived) {
						const auto serverKeyExchange = messages.find<ServerKeyExchange>();
						if (!serverKeyExchange)
							continue;
						
						this->initializeCipherData(serverKeyExchange);
						serverKeyExchangeReceived = true;
					}
				} while (!messages.find<ServerHelloDone>());
				return messages;
			}
			void initializeCipherData(const handshakes::ServerKeyExchange *serverKeyExchange) {
				using namespace handshakes;
				if (const auto range = std::ranges::remove_if(this->cipherData, [&](const CipherDataVariant &variant) {
					if (this->negotiatedCipher == Cipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
						return std::get_if<Aes128Sha256Secp256R1>(&variant) == nullptr;
					if (this->negotiatedCipher == Cipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
						return std::get_if<Aes256Sha384Secp256R1>(&variant) == nullptr;
					return true;
				}); !range.empty())
					this->cipherData.erase(range.begin(), range.end());
				
				auto &selectedCipherVariant = this->cipherData.front();
				if (const auto aes128Sha256 = std::get_if<Aes128Sha256Secp256R1>(&selectedCipherVariant); aes128Sha256 != nullptr) {
					aes128Sha256->generateKeys();
					aes128Sha256->serverPublicKey = serverKeyExchange->publicKey;
					aes128Sha256->expandKeys(this->clientRandom, this->serverRandom);
				} else if (const auto aes256Sha384 = std::get_if<Aes256Sha384Secp256R1>(&selectedCipherVariant); aes256Sha384 != nullptr) {
					aes256Sha384->generateKeys();
					aes256Sha384->serverPublicKey = serverKeyExchange->publicKey;
					aes256Sha384->expandKeys(this->clientRandom, this->serverRandom);
				}
			}
			[[nodiscard]] bool sendClientKeyExchange() {
				using namespace handshakes;

				SpanType clientPublicKey {};
				const auto &selectedCipherVariant = this->cipherData.front();
				if (const auto aes128Sha256 = std::get_if<Aes128Sha256Secp256R1>(&selectedCipherVariant); aes128Sha256 != nullptr)
					clientPublicKey = aes128Sha256->clientPublicKey;
				else if (const auto aes256Sha384 = std::get_if<Aes256Sha384Secp256R1>(&selectedCipherVariant); aes256Sha384 != nullptr)
					clientPublicKey = aes256Sha384->clientPublicKey;

				ClientKeyExchange clientKeyExchange {this->version(), clientPublicKey};
				const auto clientKeyExchangeStream = clientKeyExchange.build();
				if (!this->socket.send(clientKeyExchangeStream.data(), clientKeyExchangeStream.size()))
					return false;

				this->hashHandshake(clientKeyExchangeStream.subspan(TlsPlaintext::sizeInBytes));
				return true;
			}
			[[nodiscard]] bool sendCipherChangeSpec() const {
				using namespace handshakes;

				ChangeCipherSpecification changeCipherSpec {this->version()};
				const auto changeCipherSpecStream = changeCipherSpec.build();
				if (!this->socket.send(changeCipherSpecStream.data(), changeCipherSpecStream.size()))
					return false;

				return true;
			}
			[[nodiscard]] bool sendFinished() {
				using namespace handshakes;

				Finished finished {this->version()};
				const auto &selectedCipherVariant = this->cipherData.front();
				if (const auto aes128Sha256 = std::get_if<Aes128Sha256Secp256R1>(&selectedCipherVariant); aes128Sha256 != nullptr) {
					stream::Writer handshakeStream {};
					handshakeStream.write<std::uint8_t>(static_cast<std::uint8_t>(HandshakeType::FINISHED));
					handshakeStream.write<stream::UnsignedInt24>(12);
					handshakeStream.write(this->generateVerifyData(true));

					const auto encryptedHandshake = this->encrypt(handshakeStream, ContentType::HANDSHAKE);
					finished.iv = encryptedHandshake.subspan(0, 8);
					finished.handshake = encryptedHandshake.subspan(8);

					const auto finishedStream = finished.build();
					if (!this->socket.send(finishedStream.data(), finishedStream.size()))
						return false;
					
					this->hashHandshake(handshakeStream);
					++this->clientSequenceNumber;
					return true;
				}
				if (const auto aes256Sha384 = std::get_if<Aes256Sha384Secp256R1>(&selectedCipherVariant); aes256Sha384 != nullptr) {
					stream::Writer handshakeStream {};
					handshakeStream.write<std::uint8_t>(static_cast<std::uint8_t>(HandshakeType::FINISHED));
					handshakeStream.write<stream::UnsignedInt24>(12);
					handshakeStream.write(this->generateVerifyData(true));

					const auto encryptedHandshake = this->encrypt(handshakeStream, ContentType::HANDSHAKE);
					finished.iv = encryptedHandshake.subspan(0, 8);
					finished.handshake = encryptedHandshake.subspan(8);

					const auto finishedStream = finished.build();
					if (!this->socket.send(finishedStream.data(), finishedStream.size()))
						return false;

					this->hashHandshake(handshakeStream);
					++this->clientSequenceNumber;
					return true;
				}
				
				return false;
			}
			[[nodiscard]] bool receiveServerFinished() {
				using namespace handshakes;
				// Expect a change cipher spec message
				const auto changeCipherSpecMessage = this->receiveRecord();
				
				stream::Reader changeCipherSpecReader {changeCipherSpecMessage};
				if (const auto contentType = static_cast<ContentType>(changeCipherSpecReader.read<std::uint8_t>());
					contentType != ContentType::CHANGE_CIPHER_SPEC)
					return false;

				// Expect a finished message
				const auto finishedMessage = this->receiveRecord();

				stream::Reader finishedReader {finishedMessage};
				finishedReader.advance(TlsPlaintext::sizeInBytes);
				const auto iv = finishedReader.read<8>();
				const auto encryptedData = finishedReader.read(finishedMessage.size() - TlsPlaintext::sizeInBytes - sizeof(iv));
				
				const auto decryptedData = this->decrypt(encryptedData, iv, ContentType::HANDSHAKE);
				if (decryptedData.empty()) // Error occurred
					return false;
				
				stream::Reader dataReader {decryptedData};
				if (const auto handshakeType = static_cast<HandshakeType>(dataReader.read<std::uint8_t>());
					handshakeType != HandshakeType::FINISHED)
					return false;
				
				const auto length = dataReader.read<stream::UnsignedInt24>();
				const auto serverVerifyData = dataReader.read(length);

				if (const auto calculatedVerifyData = this->generateVerifyData(false);
					serverVerifyData != calculatedVerifyData)
					return false;

				++this->serverSequenceNumber;
				return true;
			}
			
			[[nodiscard]] stream::Writer encrypt(const SpanType data, ContentType &&type) const {
				const auto &selectedCipherVariant = this->cipherData.front();
				if (const auto aes128Sha256 = std::get_if<Aes128Sha256Secp256R1>(&selectedCipherVariant); aes128Sha256 != nullptr) {
					stream::Writer aadStream {};
					aadStream.reserve(13);
					const auto clientSequenceNumberPosition = aadStream.write<std::uint64_t>(this->clientSequenceNumber);
					aadStream.write<std::uint8_t>(static_cast<std::uint8_t>(type));
					aadStream.write<std::uint16_t>(static_cast<std::uint16_t>(this->version()));
					aadStream.write<std::uint16_t>(static_cast<std::uint16_t>(data.size()));

					const auto streamIv = aadStream.subarray<8>(clientSequenceNumberPosition);
					const aes::GcmInitializationVectorType iv = aes128Sha256->keys.clientIv() + streamIv;
					const auto encryptedData = aes::encrypt<aes::CipherMode::GCM>(data, aes128Sha256->keys.clientKey(), iv, aadStream);
					
					stream::Writer writer {};
					writer.write(streamIv);
					writer.write(encryptedData);
					return writer;
				}
				if (const auto aes256Sha384 = std::get_if<Aes256Sha384Secp256R1>(&selectedCipherVariant); aes256Sha384 != nullptr) {
					stream::Writer aadStream {};
					aadStream.reserve(13);
					const auto clientSequenceNumberPosition = aadStream.write<std::uint64_t>(this->clientSequenceNumber);
					aadStream.write<std::uint8_t>(static_cast<std::uint8_t>(type));
					aadStream.write<std::uint16_t>(static_cast<std::uint16_t>(this->version()));
					aadStream.write<std::uint16_t>(static_cast<std::uint16_t>(data.size()));

					const auto streamIv = aadStream.subarray<8>(clientSequenceNumberPosition);
					const aes::GcmInitializationVectorType iv = aes256Sha384->keys.clientIv() + streamIv;
					const auto encryptedData = aes::encrypt<aes::CipherMode::GCM>(data, aes256Sha384->keys.clientKey(), iv, aadStream);

					stream::Writer writer {};
					writer.write(streamIv);
					writer.write(encryptedData);
					return writer;
					
				}
				
				return {};
			}
			[[nodiscard]] aes::DecryptedDataType decrypt(const SpanType data, const Array<8> decryptionIv, ContentType &&type) const {
				const auto &selectedCipherVariant = this->cipherData.front();
				if (const auto aes128Sha256 = std::get_if<Aes128Sha256Secp256R1>(&selectedCipherVariant); aes128Sha256 != nullptr) {
					stream::Writer aadStream {};
					aadStream.reserve(13);
					aadStream.write<std::uint64_t>(this->serverSequenceNumber);
					aadStream.write<std::uint8_t>(static_cast<std::uint8_t>(type));
					aadStream.write<std::uint16_t>(static_cast<std::uint16_t>(this->version()));
					aadStream.write<std::uint16_t>(static_cast<std::uint16_t>(data.size()));

					const aes::GcmInitializationVectorType iv = aes128Sha256->keys.serverIv() + decryptionIv;
					return aes::decrypt<aes::CipherMode::GCM>(data, aes128Sha256->keys.serverKey(), iv, aadStream);
				}
				if (const auto aes256Sha384 = std::get_if<Aes256Sha384Secp256R1>(&selectedCipherVariant); aes256Sha384 != nullptr) {
					stream::Writer aadStream {};
					aadStream.reserve(13);
					aadStream.write<std::uint64_t>(this->serverSequenceNumber);
					aadStream.write<std::uint8_t>(static_cast<std::uint8_t>(type));
					aadStream.write<std::uint16_t>(static_cast<std::uint16_t>(this->version()));
					aadStream.write<std::uint16_t>(static_cast<std::uint16_t>(data.size() - aes::defaultTagLength));
					
					const aes::GcmInitializationVectorType iv = aes256Sha384->keys.serverIv() + decryptionIv;
					return aes::decrypt<aes::CipherMode::GCM>(data, aes256Sha384->keys.serverKey(), iv, aadStream);
				}

				return {};
			}
			
			Socket &socket;
			ProtocolVersion _version {};
			std::vector<CipherDataVariant> cipherData {};
			libtomcrypt::hash_state hashState {};
			std::size_t clientSequenceNumber {}, serverSequenceNumber {};

			Cipher negotiatedCipher {};
			RandomBuffer clientRandom {}, serverRandom {};
		};
	}
	
	struct TlsClient {
		TlsClient() = default;
		TlsClient(const std::string_view hostname, const std::string_view port) {
			this->connect(hostname, port);
		}
		
		TlsClient(const TlsClient&) = delete;
		TlsClient(TlsClient&&)      = delete;
		~TlsClient() noexcept {
			this->close();
		}
		
		auto operator =(const TlsClient&) = delete;
		auto operator =(TlsClient&&)      = delete;
		
		void connect(const std::string_view hostname, const std::string_view port) {
			if (!this->socket.connect(hostname, port))
				return;

			this->tls12Handler.add<client::Aes256Sha384Secp256R1>();
			if (!this->tls12Handler.performHandshake(hostname))
				this->socket.close();
		}
		void close() noexcept {
			this->socket.close();
		}
		
		aes::DecryptedDataType send(const SpanType data) {
			if (!this->tls12Handler.send(data)) {
				this->socket.close();
				return {};
			}

			auto response = this->tls12Handler.receive();
			if (response.empty())
				this->socket.close();
			return response;
		}
		aes::DecryptedDataType send(const std::string_view text) {
			const SpanType data {reinterpret_cast<const UnderlyingDataType*>(text.data()), text.length()};
			return this->send(data);
		}
		aes::DecryptedDataType receive() {
			return this->tls12Handler.receive();
		}
	private:
		Socket socket {};
		client::Tls12ProtocolHandler tls12Handler {socket, ProtocolVersion::VERSION_1_2};
	};
}
namespace http {
	enum struct RequestMethod {
		UNKNOWN,
		CONNECT,
		DELETE_,
		GET,
		HEAD,
		OPTIONS,
		PATCH,
		POST,
		PUT,
		TRACE
	};
	enum struct HeaderType {
		UNKNOWN,
		ACCEPT_CH,
		ACCEPT_CHARSET,
		ACCEPT_ENCODING,
		ACCEPT_LANGUAGE,
		ACCEPT_PATCH,
		ACCEPT_POST,
		ACCEPT_RANGES,
		ACCEPT,
		ACCESS_CONTROL_ALLOW_CREDENTIALS,
		ACCESS_CONTROL_ALLOW_HEADERS,
		ACCESS_CONTROL_ALLOW_METHODS,
		ACCESS_CONTROL_ALLOW_ORIGIN,
		ACCESS_CONTROL_EXPOSE_HEADERS,
		ACCESS_CONTROL_MAX_AGE,
		ACCESS_CONTROL_REQUEST_HEADERS,
		ACCESS_CONTROL_REQUEST_METHOD,
		AGE,
		ALLOW,
		ALT_SVC,
		AUTHORIZATION,
		CACHE_CONTROL,
		CLEAR_SITE_DATA,
		CONNECTION,
		CONTENT_DISPOSITION,
		CONTENT_ENCODING,
		CONTENT_LANGUAGE,
		CONTENT_LENGTH,
		CONTENT_LOCATION,
		CONTENT_RANGE,
		CONTENT_SECURITY_POLICY_REPORT_ONLY,
		CONTENT_SECURITY_POLICY,
		CONTENT_TYPE,
		COOKIE,
		CROSS_ORIGIN_EMBEDDER_POLICY,
		CROSS_ORIGIN_OPENER_POLICY,
		CROSS_ORIGIN_RESOURCE_POLICY,
		DATE,
		DEVICE_MEMORY,
		DIGEST,
		DNT,
		DOWNLINK,
		EARLY_DATA,
		ECT,
		ETAG,
		EXPECT_CT,
		EXPECT,
		EXPIRES,
		FEATURE_POLICY,
		FORWARDED,
		FROM,
		HOST,
		IF_MATCH,
		IF_MODIFIED_SINCE,
		IF_NONE_MATCH,
		IF_RANGE,
		IF_UNMODIFIED_SINCE,
		KEEP_ALIVE,
		LARGE_ALLOCATION,
		LAST_MODIFIED,
		LINK,
		LOCATION,
		NEL,
		ORIGIN,
		PROXY_AUTHENTICATE,
		PROXY_AUTHORIZATION,
		RANGE,
		REFERER,
		REFERRER_POLICY,
		RETRY_AFTER,
		RTT,
		SAVE_DATA,
		SEC_FETCH_DEST,
		SEC_FETCH_MODE,
		SEC_FETCH_SITE,
		SEC_FETCH_USER,
		SEC_WEBSOCKET_ACCEPT,
		SERVER_TIMING,
		SERVER,
		SET_COOKIE,
		SOURCEMAP,
		STRICT_TRANSPORT_SECURITY,
		TE,
		TIMING_ALLOW_ORIGIN,
		TK,
		TRAILER,
		TRANSFER_ENCODING,
		UPGRADE_INSECURE_REQUESTS,
		UPGRADE,
		USER_AGENT,
		VARY,
		VIA,
		WANT_DIGEST,
		WARNING,
		WWW_AUTHENTICATE,
		X_CONTENT_TYPE_OPTIONS,
		X_DNS_PREFETCH_CONTROL,
		X_FORWARDED_FOR,
		X_FORWARDED_HOST,
		X_FORWARDED_PROTO,
		X_FRAME_OPTIONS,
		X_XSS_PROTECTION
	};
	enum struct StatusCode {
		// Informational Responses
		CONTINUE = 100,
		SWITCHING_PROTOCOL,
		PROCESSING,
		EARLY_HINTS,

		// Successful Responses
		OK = 200,
		CREATED,
		ACCEPTED,
		NON_AUTHORITATIVE_INFORMATION,
		NO_CONTENT,
		RESET_CONTENT,
		PARTIAL_CONTENT,
		MULTI_STATUS,
		ALREADY_REPORTED,
		IM_USED = 226,

		// Redirects
		MULTI_CHOICE = 300,
		MOVED_PERMANENTLY,
		FOUND,
		SEE_OTHER,
		NOT_MODIFIED,
		USE_PROXY,
		UNUSED,
		TEMPORARY_REDIRECT,
		PERMANENT_REDIRECT,

		// Client Errors
		BAD_REQUEST = 400,
		UNAUTHORIZED,
		PAYMENT_REQUIRED,
		FORBIDDEN,
		NOT_FOUND,
		METHOD_NOT_ALLOWED,
		NOT_ACCEPTABLE,
		PROXY_AUTHENTICATION_REQUIRED,
		REQUEST_TIMEOUT,
		CONFLICT,
		GONE,
		LENGTH_REQUIRED,
		PRECONDITION_FAILED,
		PAYLOAD_TOO_LARGE,
		URI_TOO_LONG,
		UNSUPPORTED_MEDIA_TYPE,
		RANGE_NOT_SATISFIABLE,
		EXPECTATION_FAILED,
		IM_A_TEAPOT,
		MISDIRECT_REQUEST = 421,
		UNPROCESSABLE_ENTITY,
		LOCKED,
		FAILED_DEPENDENCY,
		TOO_EARLY,
		UPGRADE_REQUIRED,
		PRECONDITION_REQUIRED = 428,
		TOO_MANY_REQUESTS,
		REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
		UNAVAILABLE_FOR_LEGAL_REASONS = 451,

		// Server Errors
		INTERNAL_SERVER_ERROR = 500,
		NOT_IMPLEMENTED,
		BAD_GATEWAY,
		SERVICE_UNAVAILABLE,
		GATEWAY_TIMEOUT,
		HTTP_VERSION_NOT_SUPPORTED,
		VARIANT_ALSO_NEGOTIATES,
		INSUFFICIENT_STORAGE,
		LOOP_DETECTED,
		NOT_EXTENDED = 510,
		NETWORK_AUTHENTICATION_REQUIRED
	};
	
	std::string_view toString(const RequestMethod method) noexcept {
		if (method == RequestMethod::CONNECT)
			return "CONNECT";
		if (method == RequestMethod::DELETE_)
			return "DELETE";
		if (method == RequestMethod::GET)
			return "GET";
		if (method == RequestMethod::HEAD)
			return "HEAD";
		if (method == RequestMethod::OPTIONS)
			return "OPTIONS";
		if (method == RequestMethod::PATCH)
			return "PATCH";
		if (method == RequestMethod::POST)
			return "POST";
		if (method == RequestMethod::PUT)
			return "PUT";
		if (method == RequestMethod::TRACE)
			return "TRACE";
		return "UNKNOWN";
	}
	std::string_view toString(const HeaderType header) noexcept {
		if (header == HeaderType::ACCEPT_CH)
			return "Accept-CH";
		if (header == HeaderType::ACCEPT_CHARSET)
			return "Accept-Charset";
		if (header == HeaderType::ACCEPT_ENCODING)
			return "Accept-Encoding";
		if (header == HeaderType::ACCEPT_LANGUAGE)
			return "Accept-Language";
		if (header == HeaderType::ACCEPT_PATCH)
			return "Accept-Patch";
		if (header == HeaderType::ACCEPT_POST)
			return "Accept-Post";
		if (header == HeaderType::ACCEPT_RANGES)
			return "Accept-Ranges";
		if (header == HeaderType::ACCEPT)
			return "Accept";
		if (header == HeaderType::ACCESS_CONTROL_ALLOW_CREDENTIALS)
			return "Access-Control-Allow-Credentials";
		if (header == HeaderType::ACCESS_CONTROL_ALLOW_HEADERS)
			return "Access-Control-Allow-Headers";
		if (header == HeaderType::ACCESS_CONTROL_ALLOW_METHODS)
			return "Access-Control-Allow-Methods";
		if (header == HeaderType::ACCESS_CONTROL_ALLOW_ORIGIN)
			return "Access-Control-Allow-Origin";
		if (header == HeaderType::ACCESS_CONTROL_EXPOSE_HEADERS)
			return "Access-Control-Expose-Headers";
		if (header == HeaderType::ACCESS_CONTROL_MAX_AGE)
			return "Access-Control-Max-Age";
		if (header == HeaderType::ACCESS_CONTROL_REQUEST_HEADERS)
			return "Access-Control-Request-Headers";
		if (header == HeaderType::ACCESS_CONTROL_REQUEST_METHOD)
			return "Access-Control-Request-Method";
		if (header == HeaderType::AGE)
			return "Age";
		if (header == HeaderType::ALLOW)
			return "Allow";
		if (header == HeaderType::ALT_SVC)
			return "Alt-Svc";
		if (header == HeaderType::AUTHORIZATION)
			return "Authorization";
		if (header == HeaderType::CACHE_CONTROL)
			return "Cache-Control";
		if (header == HeaderType::CLEAR_SITE_DATA)
			return "Clear-Site-Data";
		if (header == HeaderType::CONNECTION)
			return "Connection";
		if (header == HeaderType::CONTENT_DISPOSITION)
			return "Content-Disposition";
		if (header == HeaderType::CONTENT_ENCODING)
			return "Content-Encoding";
		if (header == HeaderType::CONTENT_LANGUAGE)
			return "Content-Language";
		if (header == HeaderType::CONTENT_LENGTH)
			return "Content-Length";
		if (header == HeaderType::CONTENT_LOCATION)
			return "Content-Location";
		if (header == HeaderType::CONTENT_RANGE)
			return "Content-Range";
		if (header == HeaderType::CONTENT_SECURITY_POLICY_REPORT_ONLY)
			return "Content-Security-Policy-Report-Only";
		if (header == HeaderType::CONTENT_SECURITY_POLICY)
			return "Content-Security-Policy";
		if (header == HeaderType::CONTENT_TYPE)
			return "Content-Type";
		if (header == HeaderType::COOKIE)
			return "Cookie";
		if (header == HeaderType::CROSS_ORIGIN_EMBEDDER_POLICY)
			return "Cross-Origin-Embedder-Policy";
		if (header == HeaderType::CROSS_ORIGIN_OPENER_POLICY)
			return "Cross-Origin-Opener-Policy";
		if (header == HeaderType::CROSS_ORIGIN_RESOURCE_POLICY)
			return "Cross-Origin-Resource-Policy";
		if (header == HeaderType::DATE)
			return "Date";
		if (header == HeaderType::DEVICE_MEMORY)
			return "Device-Memory";
		if (header == HeaderType::DIGEST)
			return "Digest";
		if (header == HeaderType::DNT)
			return "DNT";
		if (header == HeaderType::DOWNLINK)
			return "Downlink";
		if (header == HeaderType::EARLY_DATA)
			return "Early-Data";
		if (header == HeaderType::ECT)
			return "ECT";
		if (header == HeaderType::ETAG)
			return "ETag";
		if (header == HeaderType::EXPECT_CT)
			return "Expect-CT";
		if (header == HeaderType::EXPECT)
			return "Expect";
		if (header == HeaderType::EXPIRES)
			return "Expires";
		if (header == HeaderType::FEATURE_POLICY)
			return "Feature-Policy";
		if (header == HeaderType::FORWARDED)
			return "Forwarded";
		if (header == HeaderType::FROM)
			return "From";
		if (header == HeaderType::HOST)
			return "Host";
		if (header == HeaderType::IF_MATCH)
			return "If-Match";
		if (header == HeaderType::IF_MODIFIED_SINCE)
			return "If-Modified-Since";
		if (header == HeaderType::IF_NONE_MATCH)
			return "If-None-Match";
		if (header == HeaderType::IF_RANGE)
			return "If-Range";
		if (header == HeaderType::IF_UNMODIFIED_SINCE)
			return "If-Unmodified-Since";
		if (header == HeaderType::KEEP_ALIVE)
			return "Keep-Alive";
		if (header == HeaderType::LARGE_ALLOCATION)
			return "Large-Allocation";
		if (header == HeaderType::LAST_MODIFIED)
			return "Last-Modified";
		if (header == HeaderType::LINK)
			return "Link";
		if (header == HeaderType::LOCATION)
			return "Location";
		if (header == HeaderType::NEL)
			return "NEL";
		if (header == HeaderType::ORIGIN)
			return "Origin";
		if (header == HeaderType::PROXY_AUTHENTICATE)
			return "Proxy-Authenticate";
		if (header == HeaderType::PROXY_AUTHORIZATION)
			return "Proxy-Authorization";
		if (header == HeaderType::RANGE)
			return "Range";
		if (header == HeaderType::REFERER)
			return "Referer";
		if (header == HeaderType::REFERRER_POLICY)
			return "Referrer-Policy";
		if (header == HeaderType::RETRY_AFTER)
			return "Retry-After";
		if (header == HeaderType::RTT)
			return "RTT";
		if (header == HeaderType::SAVE_DATA)
			return "Save-Data";
		if (header == HeaderType::SEC_FETCH_DEST)
			return "Sec-Fetch-Dest";
		if (header == HeaderType::SEC_FETCH_MODE)
			return "Sec-Fetch-Mode";
		if (header == HeaderType::SEC_FETCH_SITE)
			return "Sec-Fetch-Site";
		if (header == HeaderType::SEC_FETCH_USER)
			return "Sec-Fetch-User";
		if (header == HeaderType::SEC_WEBSOCKET_ACCEPT)
			return "Sec-WebSocket-Accept";
		if (header == HeaderType::SERVER_TIMING)
			return "Server-Timing";
		if (header == HeaderType::SERVER)
			return "Server";
		if (header == HeaderType::SET_COOKIE)
			return "Set-Cookie";
		if (header == HeaderType::SOURCEMAP)
			return "SourceMap";
		if (header == HeaderType::STRICT_TRANSPORT_SECURITY)
			return "Strict-Transport-Security";
		if (header == HeaderType::TE)
			return "TE";
		if (header == HeaderType::TIMING_ALLOW_ORIGIN)
			return "Timing-Allow-Origin";
		if (header == HeaderType::TK)
			return "Tk";
		if (header == HeaderType::TRAILER)
			return "Trailer";
		if (header == HeaderType::TRANSFER_ENCODING)
			return "Transfer-Encoding";
		if (header == HeaderType::UPGRADE_INSECURE_REQUESTS)
			return "Upgrade-Insecure-Requests";
		if (header == HeaderType::UPGRADE)
			return "Upgrade";
		if (header == HeaderType::USER_AGENT)
			return "User-Agent";
		if (header == HeaderType::VARY)
			return "Vary";
		if (header == HeaderType::VIA)
			return "Via";
		if (header == HeaderType::WANT_DIGEST)
			return "Want-Digest";
		if (header == HeaderType::WARNING)
			return "Warning";
		if (header == HeaderType::WWW_AUTHENTICATE)
			return "WWW_Authenticate";
		if (header == HeaderType::X_CONTENT_TYPE_OPTIONS)
			return "X_Content-Type-Options";
		if (header == HeaderType::X_DNS_PREFETCH_CONTROL)
			return "X_DNS_Prefetch-Control";
		if (header == HeaderType::X_FORWARDED_FOR)
			return "X_Forwarded-For";
		if (header == HeaderType::X_FORWARDED_HOST)
			return "X_Forwarded-Host";
		if (header == HeaderType::X_FORWARDED_PROTO)
			return "X_Forwarded-Proto";
		if (header == HeaderType::X_FRAME_OPTIONS)
			return "X_Frame-Options";
		if (header == HeaderType::X_XSS_PROTECTION)
			return "X_XSS_Protection";
		return "UNKNOWN";
	}
	HeaderType fromString(const std::string_view value) noexcept {
		if (value == "Accept-CH")
			return HeaderType::ACCEPT_CH;
		if (value == "Accept-Charset")
			return HeaderType::ACCEPT_CHARSET;
		if (value == "Accept-Encoding")
			return HeaderType::ACCEPT_ENCODING;
		if (value == "Accept-Language")
			return HeaderType::ACCEPT_LANGUAGE;
		if (value == "Accept-Patch")
			return HeaderType::ACCEPT_PATCH;
		if (value == "Accept-Post")
			return HeaderType::ACCEPT_POST;
		if (value == "Accept-Ranges")
			return HeaderType::ACCEPT_RANGES;
		if (value == "Accept")
			return HeaderType::ACCEPT;
		if (value == "Access-Control-Allow-Credentials")
			return HeaderType::ACCESS_CONTROL_ALLOW_CREDENTIALS;
		if (value == "Access-Control-Allow-Headers")
			return HeaderType::ACCESS_CONTROL_ALLOW_HEADERS;
		if (value == "Access-Control-Allow-Methods")
			return HeaderType::ACCESS_CONTROL_ALLOW_METHODS;
		if (value == "Access-Control-Allow-Origin")
			return HeaderType::ACCESS_CONTROL_ALLOW_ORIGIN;
		if (value == "Access-Control-Expose-Headers")
			return HeaderType::ACCESS_CONTROL_EXPOSE_HEADERS;
		if (value == "Access-Control-Max-Age")
			return HeaderType::ACCESS_CONTROL_MAX_AGE;
		if (value == "Access-Control-Request-Headers")
			return HeaderType::ACCESS_CONTROL_REQUEST_HEADERS;
		if (value == "Access-Control-Request-Method")
			return HeaderType::ACCESS_CONTROL_REQUEST_METHOD;
		if (value == "Age")
			return HeaderType::AGE;
		if (value == "Allow")
			return HeaderType::ALLOW;
		if (value == "Alt-Svc")
			return HeaderType::ALT_SVC;
		if (value == "Authorization")
			return HeaderType::AUTHORIZATION;
		if (value == "Cache-Control")
			return HeaderType::CACHE_CONTROL;
		if (value == "Clear-Site-Data")
			return HeaderType::CLEAR_SITE_DATA;
		if (value == "Connection")
			return HeaderType::CONNECTION;
		if (value == "Content-Disposition")
			return HeaderType::CONTENT_DISPOSITION;
		if (value == "Content-Encoding")
			return HeaderType::CONTENT_ENCODING;
		if (value == "Content-Language")
			return HeaderType::CONTENT_LANGUAGE;
		if (value == "Content-Length")
			return HeaderType::CONTENT_LENGTH;
		if (value == "Content-Location")
			return HeaderType::CONTENT_LOCATION;
		if (value == "Content-Range")
			return HeaderType::CONTENT_RANGE;
		if (value == "Content-Security-Policy-Report-Only")
			return HeaderType::CONTENT_SECURITY_POLICY_REPORT_ONLY;
		if (value == "Content-Security-Policy")
			return HeaderType::CONTENT_SECURITY_POLICY;
		if (value == "Content-Type")
			return HeaderType::CONTENT_TYPE;
		if (value == "Cookie")
			return HeaderType::COOKIE;
		if (value == "Cross-Origin-Embedder-Policy")
			return HeaderType::CROSS_ORIGIN_EMBEDDER_POLICY;
		if (value == "Cross-Origin-Opener-Policy")
			return HeaderType::CROSS_ORIGIN_OPENER_POLICY;
		if (value == "Cross-Origin-Resource-Policy")
			return HeaderType::CROSS_ORIGIN_RESOURCE_POLICY;
		if (value == "Date")
			return HeaderType::DATE;
		if (value == "Device-Memory")
			return HeaderType::DEVICE_MEMORY;
		if (value == "Digest")
			return HeaderType::DIGEST;
		if (value == "DNT")
			return HeaderType::DNT;
		if (value == "Downlink")
			return HeaderType::DOWNLINK;
		if (value == "Early-Data")
			return HeaderType::EARLY_DATA;
		if (value == "ECT")
			return HeaderType::ECT;
		if (value == "ETag")
			return HeaderType::ETAG;
		if (value == "Expect-CT")
			return HeaderType::EXPECT_CT;
		if (value == "Expect")
			return HeaderType::EXPECT;
		if (value == "Expires")
			return HeaderType::EXPIRES;
		if (value == "Feature-Policy")
			return HeaderType::FEATURE_POLICY;
		if (value == "Forwarded")
			return HeaderType::FORWARDED;
		if (value == "From")
			return HeaderType::FROM;
		if (value == "Host")
			return HeaderType::HOST;
		if (value == "If-Match")
			return HeaderType::IF_MATCH;
		if (value == "If-Modified-Since")
			return HeaderType::IF_MODIFIED_SINCE;
		if (value == "If-None-Match")
			return HeaderType::IF_NONE_MATCH;
		if (value == "If-Range")
			return HeaderType::IF_RANGE;
		if (value == "If-Unmodified-Since")
			return HeaderType::IF_UNMODIFIED_SINCE;
		if (value == "Keep-Alive")
			return HeaderType::KEEP_ALIVE;
		if (value == "Large-Allocation")
			return HeaderType::LARGE_ALLOCATION;
		if (value == "Last-Modified")
			return HeaderType::LAST_MODIFIED;
		if (value == "Link")
			return HeaderType::LINK;
		if (value == "Location")
			return HeaderType::LOCATION;
		if (value == "NEL")
			return HeaderType::NEL;
		if (value == "Origin")
			return HeaderType::ORIGIN;
		if (value == "Proxy-Authenticate")
			return HeaderType::PROXY_AUTHENTICATE;
		if (value == "Proxy-Authorization")
			return HeaderType::PROXY_AUTHORIZATION;
		if (value == "Range")
			return HeaderType::RANGE;
		if (value == "Referer")
			return HeaderType::REFERER;
		if (value == "Referrer-Policy")
			return HeaderType::REFERRER_POLICY;
		if (value == "Retry-After")
			return HeaderType::RETRY_AFTER;
		if (value == "RTT")
			return HeaderType::RTT;
		if (value == "Save-Data")
			return HeaderType::SAVE_DATA;
		if (value == "Sec-Fetch-Dest")
			return HeaderType::SEC_FETCH_DEST;
		if (value == "Sec-Fetch-Mode")
			return HeaderType::SEC_FETCH_MODE;
		if (value == "Sec-Fetch-Site")
			return HeaderType::SEC_FETCH_SITE;
		if (value == "Sec-Fetch-User")
			return HeaderType::SEC_FETCH_USER;
		if (value == "Sec-WebSocket-Accept")
			return HeaderType::SEC_WEBSOCKET_ACCEPT;
		if (value == "Server-Timing")
			return HeaderType::SERVER_TIMING;
		if (value == "Server")
			return HeaderType::SERVER;
		if (value == "Set-Cookie")
			return HeaderType::SET_COOKIE;
		if (value == "SourceMap")
			return HeaderType::SOURCEMAP;
		if (value == "Strict-Transport-Security")
			return HeaderType::STRICT_TRANSPORT_SECURITY;
		if (value == "TE")
			return HeaderType::TE;
		if (value == "Timing-Allow-Origin")
			return HeaderType::TIMING_ALLOW_ORIGIN;
		if (value == "Tk")
			return HeaderType::TK;
		if (value == "Trailer")
			return HeaderType::TRAILER;
		if (value == "Transfer-Encoding")
			return HeaderType::TRANSFER_ENCODING;
		if (value == "Upgrade-Insecure-Requests")
			return HeaderType::UPGRADE_INSECURE_REQUESTS;
		if (value == "Upgrade")
			return HeaderType::UPGRADE;
		if (value == "User-Agent")
			return HeaderType::USER_AGENT;
		if (value == "Vary")
			return HeaderType::VARY;
		if (value == "Via")
			return HeaderType::VIA;
		if (value == "Want-Digest")
			return HeaderType::WANT_DIGEST;
		if (value == "Warning")
			return HeaderType::WARNING;
		if (value == "WWW_Authenticate")
			return HeaderType::WWW_AUTHENTICATE;
		if (value == "X_Content-Type-Options")
			return HeaderType::X_CONTENT_TYPE_OPTIONS;
		if (value == "X_DNS_Prefetch-Control")
			return HeaderType::X_DNS_PREFETCH_CONTROL;
		if (value == "X_Forwarded-For")
			return HeaderType::X_FORWARDED_FOR;
		if (value == "X_Forwarded-Host")
			return HeaderType::X_FORWARDED_HOST;
		if (value == "X_Forwarded-Proto")
			return HeaderType::X_FORWARDED_PROTO;
		if (value == "X_Frame-Options")
			return HeaderType::X_FRAME_OPTIONS;
		if (value == "X_XSS_Protection")
			return HeaderType::X_XSS_PROTECTION;
		return HeaderType::UNKNOWN;
	}
	
	struct Header {
		HeaderType  header {};
		std::string value {};
		
		Header(const HeaderType header, const std::string_view value):
			header {header}, value {value} {}
	};

	std::pair<std::string_view, std::string_view> parseUri(const std::string_view uri) noexcept {
		constexpr std::string_view protocolDelimiter {"://"};
		if (const auto hostOffset = uri.find(protocolDelimiter);
			hostOffset != std::string_view::npos) {
			if (const auto dataOffset = uri.find_first_of('/', hostOffset + protocolDelimiter.length());
				dataOffset != std::string_view::npos)
				return {uri.substr(hostOffset + protocolDelimiter.length(), dataOffset - hostOffset - protocolDelimiter.length()), uri.substr(dataOffset)};
			return {uri.substr(hostOffset + protocolDelimiter.length()), {}};
		}
		if (const auto dataOffset = uri.find_first_of('/');
			dataOffset != std::string_view::npos)
			return {uri.substr(0, dataOffset), uri.substr(dataOffset)};
		return {uri, {}};
	}
}
namespace http11 { // HTTP/1.1
	using UnderlyingDataType = tls::UnderlyingDataType;
	using SpanType = tls::SpanType;
	using HeadersContainerType = std::vector<http::Header>;
	using ContentContainerType = std::vector<UnderlyingDataType>;

	struct Request {
		using BufferType = std::vector<UnderlyingDataType>;

		Request() = default;
		Request(const http::RequestMethod method, const std::string_view uri):
			_method {method} {
			const auto [host, data] = http::parseUri(uri);
			if (!data.empty())
				this->data(data);
			if (!host.empty())
				this->header(http::HeaderType::HOST, host);
		}
		Request(const http::RequestMethod method, const std::string_view host, const std::string_view data):
			_method {method}, _data {data} {
			this->header(http::HeaderType::HOST, host);
		}

		void method(const http::RequestMethod method) noexcept {
			this->_method = method;
		}
		void data(const std::string_view data) noexcept {
			this->_data = data;
		}
		void header(const http::HeaderType headerType, const std::string_view value) {
			if (const auto iterator = std::ranges::find_if(this->_headers, [&](const decltype(this->_headers)::value_type &entry) {
				return entry.header == headerType;
			}); iterator != this->_headers.end())
				iterator->value = value;
			else
				this->_headers.emplace_back(headerType, value);
		}

		// Content specific functions
		void set(const SpanType data) {
			if (data.empty())
				return;
			
			this->_content.clear();
			this->_content.reserve(data.size());

			this->_content.insert(this->_content.begin(), data.begin(), data.end());

			tls::Array<20> buffer {};
			const auto bufferData = reinterpret_cast<char*>(buffer.data());
			if (const auto [pointer, error] = std::to_chars(bufferData, bufferData + buffer.size(), this->_content.size());
				error != std::errc {})
				this->header(http::HeaderType::CONTENT_LENGTH, bufferData);
		}
		void set(const std::string_view data) {
			this->set(SpanType {reinterpret_cast<const UnderlyingDataType*>(data.data()), data.size()});
		}
		void append(const SpanType data) {
			if (data.empty())
				return;

			this->_content.reserve(this->_content.size() + data.size());
			this->_content.insert(this->_content.begin(), data.begin(), data.end());

			tls::Array<20> buffer {};
			const auto bufferData = reinterpret_cast<char*>(buffer.data());
			if (const auto [pointer, error] = std::to_chars(bufferData, bufferData + buffer.size(), this->_content.size());
				error != std::errc {})
				this->header(http::HeaderType::CONTENT_LENGTH, bufferData);
		}
		void append(const std::string_view data) {
			this->append(SpanType {reinterpret_cast<const UnderlyingDataType*>(data.data()), data.size()});
		}

		// Builder
		BufferType build() {
			constexpr std::string_view crlf {"\r\n"};

			if (this->_method == http::RequestMethod::UNKNOWN)
				return {};
			
			BufferType buffer {};

			// Method + data + HTTP Protocol Version + CRLF
			{
				constexpr std::string_view format {R"(%s %s HTTP/1.1%s)"};

				const auto requestMethodText = http::toString(this->_method);
				const auto requiredSize = _snprintf(nullptr, 0, format.data(), requestMethodText.data(), this->_data.data(), crlf.data()) + 1;
				buffer.resize(buffer.size() + requiredSize);
				_snprintf_s(reinterpret_cast<char*>(buffer.data()), requiredSize, _TRUNCATE, format.data(), requestMethodText.data(), this->_data.data(), crlf.data());
				buffer.resize(buffer.size() - 1);
			}

			// Headers
			{
				this->header(http::HeaderType::CONNECTION, "close"); // set `Connection: close`
				
				constexpr std::string_view format {R"(%s: %s%s)"};
				for (const auto &[header, value] : this->_headers) {
					const auto headerText = http::toString(header);
					
					const auto previousSize = buffer.size();
					const auto requiredSize = _snprintf(nullptr, 0, format.data(), headerText.data(), value.data(), crlf.data()) + 1;
					buffer.resize(previousSize + requiredSize);
					_snprintf_s(reinterpret_cast<char*>(buffer.data() + previousSize), requiredSize, _TRUNCATE, format.data(), headerText.data(), value.data(), crlf.data());
					buffer.resize(buffer.size() - 1);
				}
			}

			// Append last CRLF
			buffer.resize(buffer.size() + crlf.size());
			std::memcpy(buffer.data() + buffer.size() - crlf.size(), crlf.data(), crlf.size());
			
			// Content
			if (!this->_content.empty()) {
				buffer.resize(buffer.size() + this->_content.size());
				std::memcpy(buffer.data() + buffer.size() - this->_content.size(), this->_content.data(), this->_content.size());
			}
			
			return buffer;
		}
		
		HeadersContainerType &headers() noexcept {
			return this->_headers;
		}
		[[nodiscard]] const HeadersContainerType &headers() const noexcept {
			return this->_headers;
		}
		ContentContainerType &content() noexcept {
			return this->_content;
		}
		[[nodiscard]] const ContentContainerType &content() const noexcept {
			return this->_content;
		}
	private:
		http::RequestMethod _method {http::RequestMethod::UNKNOWN};
		std::string_view _data {};
		
		HeadersContainerType _headers {};
		ContentContainerType _content {};
	};
	struct Response {
		std::string_view header(const http::HeaderType headerType) {
			if (const auto iterator = std::ranges::find_if(std::as_const(this->_headers), [&](const decltype(this->_headers)::value_type &entry) {
				return entry.header == headerType;
			}); iterator != this->_headers.cend())
				return iterator->value;

			return {};
		}
		
		[[nodiscard]] std::pair<std::size_t, std::size_t> parse(const SpanType responseBuffer) {
			constexpr std::string_view crlf {"\r\n"};
			const std::string_view response {reinterpret_cast<const char*>(responseBuffer.data()), responseBuffer.size()};

			// HTTP protocol version + status (error code + message) + CRLF
			{
				if (!response.starts_with("HTTP/1.1"))
					return {};

				const auto statusCodeStartOffset = response.find(' ');
				if (statusCodeStartOffset == std::string::npos)
					return {};

				const auto statusCodeEndOffset = response.find(' ', statusCodeStartOffset + 1);
				if (statusCodeEndOffset == std::string::npos)
					return {};

				const auto statusCodeStart = response.data() + statusCodeStartOffset + 1;
				const auto statusCodeEnd   = response.data() + statusCodeEndOffset;
				
				std::int32_t statusCode {};
				if (const auto [x, ec] = std::from_chars(statusCodeStart, statusCodeEnd, statusCode);
					ec != std::errc {})
					return {};
				this->statusCode = static_cast<http::StatusCode>(statusCode);
			}

			// Headers
			constexpr tls::Array<4> endBuffer {'\r', '\n', '\r', '\n'};
			const auto begin = response.find(crlf);
			if (begin == std::string_view::npos)
				return {};
			
			const auto end = response.find({reinterpret_cast<const char*>(endBuffer.data()), 4}, begin + crlf.size());
			{
				constexpr auto headerDelimiter {':'};
				for (auto offset = begin + crlf.size(); offset < end;) {
					const auto next = response.find(crlf, offset);
					const auto headerText = response.substr(offset, next - offset);

					const auto delimiterOffset = headerText.find_first_of(headerDelimiter);
					if (delimiterOffset == std::string_view::npos)
						return {};
					
					const auto headerType = http::fromString(headerText.substr(0, delimiterOffset));
					
					const auto valueBegin = headerText.find_first_not_of(' ', delimiterOffset + 1);
					const auto value = headerText.substr(valueBegin);
					this->_headers.emplace_back(headerType, value);

					offset = next + crlf.size();
				}
			}

			const auto contentLength = this->header(http::HeaderType::CONTENT_LENGTH);
			if (contentLength.empty())
				return {};

			std::int32_t value {};
			if (const auto [pointer, error] = std::from_chars(contentLength.data(), contentLength.data() + contentLength.size(), value);
				error == std::errc {})
				return {value, end + endBuffer.size()};
			return {0, response.size()};
		}
		[[nodiscard]] std::optional<tls::aes::DecryptedDataType> receive(const SpanType initialResponseBuffer, tls::TlsClient &client) {
			const auto [contentLength, headerSize] = this->parse(initialResponseBuffer);
			if (!contentLength || !headerSize)
				return std::nullopt;

			tls::aes::DecryptedDataType decryptedDataBuffer {};
			decryptedDataBuffer.resize(contentLength);

			const auto initialDataSize = initialResponseBuffer.size() - headerSize;
			std::memcpy(decryptedDataBuffer.data(), initialResponseBuffer.data() + headerSize, initialDataSize);

			auto offset {initialDataSize};
			while (offset < contentLength) {
				const auto temporary = client.receive();
				std::memcpy(decryptedDataBuffer.data() + offset, temporary.data(), temporary.size());
				offset += temporary.size();
			}

			return decryptedDataBuffer;
		}
		
		http::StatusCode statusCode {};
		HeadersContainerType _headers {};
	};
}

void performTlsConnection() {
	using namespace tls;
	using namespace handshakes;

	TlsClient msdlClient {"msdl.microsoft.com", "443"};
	http11::Request msdlRequest {http::RequestMethod::GET, "https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/3F2AAB0149AB6278D915DE1350D0FED91/ntkrnlmp.pdb"};
	const auto msdlResponseData = msdlClient.send(msdlRequest.build());

	http11::Response msdlResponse {};
	{
		[[maybe_unused]] const auto [contentLength, headerSize] = msdlResponse.parse(msdlResponseData);
	}
	msdlClient.close();

	if (msdlResponse.statusCode != http::StatusCode::FOUND)
		return;

	const auto newLocation = msdlResponse.header(http::HeaderType::LOCATION);
	if (newLocation.empty())
		return;

	const auto [redirectHost, redirectData] = http::parseUri(newLocation);
	
	TlsClient cdnClient {redirectHost, "443"};
	http11::Request cdnRequest {http::RequestMethod::GET, redirectHost, redirectData};
	const auto cdnResponseData = cdnClient.send(cdnRequest.build());

	http11::Response cdnResponse {};
	const auto decryptedContent = cdnResponse.receive(cdnResponseData, cdnClient);
	cdnClient.close();
	
	return;

	/*
	* TlsPlaintext (content type - Alert, protocol version (2 bytes), length (2 bytes))
	* Alert (alert level, alert description)
	*/

	/*
	 * At this point we should call recv:
	 *   - read first 5 bytes: raw sizeof(TlsPlaintext)
	 *   - decode TlsPlaintext (get the size of the remaining buffer)
	 *   - read the messages
	 * Note: in reality the server could send multiple packets (TlsPlaintext entries), we need to combine the parsed messages until we receive a "Server Hello Done" message
	 */

	//const parser::MessageVariant parsedMessages {messages};
	//const auto parsedMessages = parser::parseHandshakeMessages(serverResponse);
	//const auto parsedMessages = parser::parseHandshakeMessages(alertBytes.data(), alertBytes.size());
	//const auto parsedMessages = parser::parseHandshakeMessages(serverHelloBytes.data(), serverHelloBytes.size());
	#pragma region PARSED_MESSAGES
	/*if (const auto error = std::get_if<parser::ErrorType>(&parsedMessages))
		fmt::print(FMT_STRING("Error parsing the server response: {}\n"), static_cast<std::underlying_type_t<parser::ErrorType>>(*error));
	else if (const auto alert = std::get_if<alerts::Alert>(&parsedMessages)) {
		auto level {"Unknown"}, description {"Unknown"};
		{
			if (alert->level == alerts::AlertLevel::WARNING)
				level = "WARNING";
			else if (alert->level == alerts::AlertLevel::FATAL)
				level = "FATAL";

			#define ALERT_DESCRIPTION(X) if (alert->description == alerts::AlertDescription::X) description = #X  // NOLINT(cppcoreguidelines-macro-usage)

			ALERT_DESCRIPTION(CLOSE_NOTIFY);
			ALERT_DESCRIPTION(UNEXPECTED_MESSAGE);
			ALERT_DESCRIPTION(BAD_RECORD_MAC);
			ALERT_DESCRIPTION(DECRYPTION_FAILED);
			ALERT_DESCRIPTION(RECORD_OVERFLOW);
			ALERT_DESCRIPTION(DECOMPRESSION_FAILURE);
			ALERT_DESCRIPTION(HANDSHAKE_FAILURE);
			ALERT_DESCRIPTION(NO_CERTIFICATE);
			ALERT_DESCRIPTION(BAD_CERTIFICATE);
			ALERT_DESCRIPTION(UNSUPPORTED_CERTIFICATE);
			ALERT_DESCRIPTION(CERTIFICATE_REVOKED);
			ALERT_DESCRIPTION(CERTIFICATE_EXPIRED);
			ALERT_DESCRIPTION(CERTIFICATE_UNKNOWN);
			ALERT_DESCRIPTION(ILLEGAL_PARAMETER);
			ALERT_DESCRIPTION(UNKNOWN_CA);
			ALERT_DESCRIPTION(ACCESS_DENIED);
			ALERT_DESCRIPTION(DECODE_ERROR);
			ALERT_DESCRIPTION(DECRYPT_ERROR);
			ALERT_DESCRIPTION(EXPORT_RESTRICTION);
			ALERT_DESCRIPTION(PROTOCOL_VERSION);
			ALERT_DESCRIPTION(INSUFFICIENT_SECURITY);
			ALERT_DESCRIPTION(INTERNAL_ERROR);
			ALERT_DESCRIPTION(INAPPROPRIATE_FALLBACK);
			ALERT_DESCRIPTION(USER_CANCELED);
			ALERT_DESCRIPTION(NO_RENEGOTIATION);
			ALERT_DESCRIPTION(MISSING_EXTENSION);
			ALERT_DESCRIPTION(UNSUPPORTED_EXTENSION);
			ALERT_DESCRIPTION(CERTIFICATE_UNOBTAINABLE);
			ALERT_DESCRIPTION(UNRECOGNIZED_NAME);
			ALERT_DESCRIPTION(BAD_CERTIFICATE_STATUS_RESPONSE);
			ALERT_DESCRIPTION(BAD_CERTIFICATE_HASH_VALUE);
			ALERT_DESCRIPTION(UNKNOWN_PSK_IDENTITY);
			ALERT_DESCRIPTION(CERTIFICATE_REQUIRED);
			ALERT_DESCRIPTION(NO_APPLICATION_PROTOCOL);
		}
		
		fmt::print(FMT_STRING("Alert:\n - Level: {}\n - Description: {}\n"), level, description);
	} else if (const auto messages = std::get_if<parser::MessageVector>(&parsedMessages)) {
		fmt::print(FMT_STRING("Received {} messages from the server:\n"), messages->size());
		for (const auto &message : *messages) {
			if (const auto serverHello = std::get_if<ServerHello>(&message)) {
				#pragma region ServerHello
				auto serverVersion {"Unknown"};
				{
					if (serverHello->serverVersion == ProtocolVersion::VERSION_1_0)
						serverVersion = "TLS 1.0";
					else if (serverHello->serverVersion == ProtocolVersion::VERSION_1_1)
						serverVersion = "TLS 1.1";
					else if (serverHello->serverVersion == ProtocolVersion::VERSION_1_2)
						serverVersion = "TLS 1.2";
					else if (serverHello->serverVersion == ProtocolVersion::VERSION_1_3)
						serverVersion = "TLS 1.3";
				}

				fmt::memory_buffer randomBytesMemoryBuffer {};
				for (std::size_t i {}; auto &&byte : serverHello->random.data) {
					if (++i < serverHello->random.data.size())
						if (i % 16 == 0)
							fmt::format_to(randomBytesMemoryBuffer, FMT_STRING("{:02X}\n       "), byte);
						else
							fmt::format_to(randomBytesMemoryBuffer, FMT_STRING("{:02X} "), byte);
					else
						fmt::format_to(randomBytesMemoryBuffer, FMT_STRING("{:02X}"), byte);
				}

				fmt::memory_buffer sessionIdMemoryBuffer {};
				for (std::size_t i {}; auto &&byte : serverHello->sessionId.data) {
					if (++i < serverHello->sessionId.data.size())
						if (i % 16 == 0)
							fmt::format_to(sessionIdMemoryBuffer, FMT_STRING("{:02X}\n       "), byte);
						else
							fmt::format_to(sessionIdMemoryBuffer, FMT_STRING("{:02X} "), byte);
					else
						fmt::format_to(sessionIdMemoryBuffer, FMT_STRING("{:02X}"), byte);
				}

				auto cipher {"Unknown"};
				{
					#define CIPHER(X) if (serverHello->cipher == Cipher::X) cipher = #X  // NOLINT(cppcoreguidelines-macro-usage)

					CIPHER(TLS_NULL_WITH_NULL_NULL);
					CIPHER(TLS_RSA_WITH_NULL_MD5);
					CIPHER(TLS_RSA_WITH_NULL_SHA);
					CIPHER(TLS_RSA_EXPORT_WITH_RC4_40_MD5);
					CIPHER(TLS_RSA_WITH_RC4_128_MD5);
					CIPHER(TLS_RSA_WITH_RC4_128_SHA);
					CIPHER(TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5);
					CIPHER(TLS_RSA_WITH_IDEA_CBC_SHA);
					CIPHER(TLS_RSA_EXPORT_WITH_DES40_CBC_SHA);
					CIPHER(TLS_RSA_WITH_DES_CBC_SHA);
					CIPHER(TLS_RSA_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA);
					CIPHER(TLS_DH_DSS_WITH_DES_CBC_SHA);
					CIPHER(TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA);
					CIPHER(TLS_DH_RSA_WITH_DES_CBC_SHA);
					CIPHER(TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);
					CIPHER(TLS_DHE_DSS_WITH_DES_CBC_SHA);
					CIPHER(TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA);
					CIPHER(TLS_DHE_RSA_WITH_DES_CBC_SHA);
					CIPHER(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_DH_anon_EXPORT_WITH_RC4_40_MD5);
					CIPHER(TLS_DH_anon_WITH_RC4_128_MD5);
					CIPHER(TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA);
					CIPHER(TLS_DH_anon_WITH_DES_CBC_SHA);
					CIPHER(TLS_DH_anon_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_KRB5_WITH_DES_CBC_SHA);
					CIPHER(TLS_KRB5_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_KRB5_WITH_RC4_128_SHA);
					CIPHER(TLS_KRB5_WITH_IDEA_CBC_SHA);
					CIPHER(TLS_KRB5_WITH_DES_CBC_MD5);
					CIPHER(TLS_KRB5_WITH_3DES_EDE_CBC_MD5);
					CIPHER(TLS_KRB5_WITH_RC4_128_MD5);
					CIPHER(TLS_KRB5_WITH_IDEA_CBC_MD5);
					CIPHER(TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA);
					CIPHER(TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA);
					CIPHER(TLS_KRB5_EXPORT_WITH_RC4_40_SHA);
					CIPHER(TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5);
					CIPHER(TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5);
					CIPHER(TLS_KRB5_EXPORT_WITH_RC4_40_MD5);
					CIPHER(TLS_PSK_WITH_NULL_SHA);
					CIPHER(TLS_DHE_PSK_WITH_NULL_SHA);
					CIPHER(TLS_RSA_PSK_WITH_NULL_SHA);
					CIPHER(TLS_RSA_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_DH_DSS_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_DH_RSA_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_DH_anon_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_RSA_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_DH_DSS_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_DH_RSA_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_DH_anon_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_RSA_WITH_NULL_SHA256);
					CIPHER(TLS_RSA_WITH_AES_128_CBC_SHA256);
					CIPHER(TLS_RSA_WITH_AES_256_CBC_SHA256);
					CIPHER(TLS_DH_DSS_WITH_AES_128_CBC_SHA256);
					CIPHER(TLS_DH_RSA_WITH_AES_128_CBC_SHA256);
					CIPHER(TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
					CIPHER(TLS_RSA_WITH_CAMELLIA_128_CBC_SHA);
					CIPHER(TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA);
					CIPHER(TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA);
					CIPHER(TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA);
					CIPHER(TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA);
					CIPHER(TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA);
					CIPHER(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
					CIPHER(TLS_DH_DSS_WITH_AES_256_CBC_SHA256);
					CIPHER(TLS_DH_RSA_WITH_AES_256_CBC_SHA256);
					CIPHER(TLS_DHE_DSS_WITH_AES_256_CBC_SHA256);
					CIPHER(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
					CIPHER(TLS_DH_anon_WITH_AES_128_CBC_SHA256);
					CIPHER(TLS_DH_anon_WITH_AES_256_CBC_SHA256);
					CIPHER(TLS_RSA_WITH_CAMELLIA_256_CBC_SHA);
					CIPHER(TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA);
					CIPHER(TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA);
					CIPHER(TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA);
					CIPHER(TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA);
					CIPHER(TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA);
					CIPHER(TLS_PSK_WITH_RC4_128_SHA);
					CIPHER(TLS_PSK_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_PSK_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_PSK_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_DHE_PSK_WITH_RC4_128_SHA);
					CIPHER(TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_DHE_PSK_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_DHE_PSK_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_RSA_PSK_WITH_RC4_128_SHA);
					CIPHER(TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_RSA_PSK_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_RSA_PSK_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_RSA_WITH_SEED_CBC_SHA);
					CIPHER(TLS_DH_DSS_WITH_SEED_CBC_SHA);
					CIPHER(TLS_DH_RSA_WITH_SEED_CBC_SHA);
					CIPHER(TLS_DHE_DSS_WITH_SEED_CBC_SHA);
					CIPHER(TLS_DHE_RSA_WITH_SEED_CBC_SHA);
					CIPHER(TLS_DH_anon_WITH_SEED_CBC_SHA);
					CIPHER(TLS_RSA_WITH_AES_128_GCM_SHA256);
					CIPHER(TLS_RSA_WITH_AES_256_GCM_SHA384);
					CIPHER(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
					CIPHER(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
					CIPHER(TLS_DH_RSA_WITH_AES_128_GCM_SHA256);
					CIPHER(TLS_DH_RSA_WITH_AES_256_GCM_SHA384);
					CIPHER(TLS_DHE_DSS_WITH_AES_128_GCM_SHA256);
					CIPHER(TLS_DHE_DSS_WITH_AES_256_GCM_SHA384);
					CIPHER(TLS_DH_DSS_WITH_AES_128_GCM_SHA256);
					CIPHER(TLS_DH_DSS_WITH_AES_256_GCM_SHA384);
					CIPHER(TLS_DH_anon_WITH_AES_128_GCM_SHA256);
					CIPHER(TLS_DH_anon_WITH_AES_256_GCM_SHA384);
					CIPHER(TLS_PSK_WITH_AES_128_GCM_SHA256);
					CIPHER(TLS_PSK_WITH_AES_256_GCM_SHA384);
					CIPHER(TLS_DHE_PSK_WITH_AES_128_GCM_SHA256);
					CIPHER(TLS_DHE_PSK_WITH_AES_256_GCM_SHA384);
					CIPHER(TLS_RSA_PSK_WITH_AES_128_GCM_SHA256);
					CIPHER(TLS_RSA_PSK_WITH_AES_256_GCM_SHA384);
					CIPHER(TLS_PSK_WITH_AES_128_CBC_SHA256);
					CIPHER(TLS_PSK_WITH_AES_256_CBC_SHA384);
					CIPHER(TLS_PSK_WITH_NULL_SHA256);
					CIPHER(TLS_PSK_WITH_NULL_SHA384);
					CIPHER(TLS_DHE_PSK_WITH_AES_128_CBC_SHA256);
					CIPHER(TLS_DHE_PSK_WITH_AES_256_CBC_SHA384);
					CIPHER(TLS_DHE_PSK_WITH_NULL_SHA256);
					CIPHER(TLS_DHE_PSK_WITH_NULL_SHA384);
					CIPHER(TLS_RSA_PSK_WITH_AES_128_CBC_SHA256);
					CIPHER(TLS_RSA_PSK_WITH_AES_256_CBC_SHA384);
					CIPHER(TLS_RSA_PSK_WITH_NULL_SHA256);
					CIPHER(TLS_RSA_PSK_WITH_NULL_SHA384);
					CIPHER(TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256);
					CIPHER(TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256);
					CIPHER(TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256);
					CIPHER(TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256);
					CIPHER(TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256);
					CIPHER(TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256);
					CIPHER(TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256);
					CIPHER(TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256);
					CIPHER(TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256);
					CIPHER(TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256);
					CIPHER(TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256);
					CIPHER(TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256);
					CIPHER(TLS_SM4_GCM_SM3);
					CIPHER(TLS_SM4_CCM_SM3);
					CIPHER(TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
					CIPHER(TLS_AES_128_GCM_SHA256);
					CIPHER(TLS_AES_256_GCM_SHA384);
					CIPHER(TLS_CHACHA20_POLY1305_SHA256);
					CIPHER(TLS_AES_128_CCM_SHA256);
					CIPHER(TLS_AES_128_CCM_8_SHA256);
					CIPHER(TLS_FALLBACK_SCSV);
					CIPHER(TLS_ECDH_ECDSA_WITH_NULL_SHA);
					CIPHER(TLS_ECDH_ECDSA_WITH_RC4_128_SHA);
					CIPHER(TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_ECDHE_ECDSA_WITH_NULL_SHA);
					CIPHER(TLS_ECDHE_ECDSA_WITH_RC4_128_SHA);
					CIPHER(TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_ECDH_RSA_WITH_NULL_SHA);
					CIPHER(TLS_ECDH_RSA_WITH_RC4_128_SHA);
					CIPHER(TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_ECDHE_RSA_WITH_NULL_SHA);
					CIPHER(TLS_ECDHE_RSA_WITH_RC4_128_SHA);
					CIPHER(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_ECDH_anon_WITH_NULL_SHA);
					CIPHER(TLS_ECDH_anon_WITH_RC4_128_SHA);
					CIPHER(TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_ECDH_anon_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_ECDH_anon_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_SRP_SHA_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_SRP_SHA_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
					CIPHER(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
					CIPHER(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256);
					CIPHER(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384);
					CIPHER(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
					CIPHER(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
					CIPHER(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256);
					CIPHER(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384);
					CIPHER(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
					CIPHER(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
					CIPHER(TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256);
					CIPHER(TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384);
					CIPHER(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
					CIPHER(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
					CIPHER(TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256);
					CIPHER(TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384);
					CIPHER(TLS_ECDHE_PSK_WITH_RC4_128_SHA);
					CIPHER(TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA);
					CIPHER(TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA);
					CIPHER(TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA);
					CIPHER(TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256);
					CIPHER(TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384);
					CIPHER(TLS_ECDHE_PSK_WITH_NULL_SHA);
					CIPHER(TLS_ECDHE_PSK_WITH_NULL_SHA256);
					CIPHER(TLS_ECDHE_PSK_WITH_NULL_SHA384);
					CIPHER(TLS_RSA_WITH_ARIA_128_CBC_SHA256);
					CIPHER(TLS_RSA_WITH_ARIA_256_CBC_SHA384);
					CIPHER(TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256);
					CIPHER(TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384);
					CIPHER(TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256);
					CIPHER(TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384);
					CIPHER(TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256);
					CIPHER(TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384);
					CIPHER(TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256);
					CIPHER(TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384);
					CIPHER(TLS_DH_anon_WITH_ARIA_128_CBC_SHA256);
					CIPHER(TLS_DH_anon_WITH_ARIA_256_CBC_SHA384);
					CIPHER(TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256);
					CIPHER(TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384);
					CIPHER(TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256);
					CIPHER(TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384);
					CIPHER(TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256);
					CIPHER(TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384);
					CIPHER(TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256);
					CIPHER(TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384);
					CIPHER(TLS_RSA_WITH_ARIA_128_GCM_SHA256);
					CIPHER(TLS_RSA_WITH_ARIA_256_GCM_SHA384);
					CIPHER(TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256);
					CIPHER(TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384);
					CIPHER(TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256);
					CIPHER(TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384);
					CIPHER(TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256);
					CIPHER(TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384);
					CIPHER(TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256);
					CIPHER(TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384);
					CIPHER(TLS_DH_anon_WITH_ARIA_128_GCM_SHA256);
					CIPHER(TLS_DH_anon_WITH_ARIA_256_GCM_SHA384);
					CIPHER(TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256);
					CIPHER(TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384);
					CIPHER(TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256);
					CIPHER(TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384);
					CIPHER(TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256);
					CIPHER(TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384);
					CIPHER(TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256);
					CIPHER(TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384);
					CIPHER(TLS_PSK_WITH_ARIA_128_CBC_SHA256);
					CIPHER(TLS_PSK_WITH_ARIA_256_CBC_SHA384);
					CIPHER(TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256);
					CIPHER(TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384);
					CIPHER(TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256);
					CIPHER(TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384);
					CIPHER(TLS_PSK_WITH_ARIA_128_GCM_SHA256);
					CIPHER(TLS_PSK_WITH_ARIA_256_GCM_SHA384);
					CIPHER(TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256);
					CIPHER(TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384);
					CIPHER(TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256);
					CIPHER(TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384);
					CIPHER(TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256);
					CIPHER(TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384);
					CIPHER(TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256);
					CIPHER(TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384);
					CIPHER(TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256);
					CIPHER(TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384);
					CIPHER(TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256);
					CIPHER(TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384);
					CIPHER(TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256);
					CIPHER(TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384);
					CIPHER(TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256);
					CIPHER(TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384);
					CIPHER(TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256);
					CIPHER(TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384);
					CIPHER(TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256);
					CIPHER(TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384);
					CIPHER(TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256);
					CIPHER(TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384);
					CIPHER(TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256);
					CIPHER(TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384);
					CIPHER(TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256);
					CIPHER(TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384);
					CIPHER(TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256);
					CIPHER(TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384);
					CIPHER(TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256);
					CIPHER(TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384);
					CIPHER(TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256);
					CIPHER(TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384);
					CIPHER(TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256);
					CIPHER(TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384);
					CIPHER(TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256);
					CIPHER(TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384);
					CIPHER(TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256);
					CIPHER(TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384);
					CIPHER(TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256);
					CIPHER(TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384);
					CIPHER(TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256);
					CIPHER(TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384);
					CIPHER(TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256);
					CIPHER(TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384);
					CIPHER(TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256);
					CIPHER(TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384);
					CIPHER(TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256);
					CIPHER(TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384);
					CIPHER(TLS_RSA_WITH_AES_128_CCM);
					CIPHER(TLS_RSA_WITH_AES_256_CCM);
					CIPHER(TLS_DHE_RSA_WITH_AES_128_CCM);
					CIPHER(TLS_DHE_RSA_WITH_AES_256_CCM);
					CIPHER(TLS_RSA_WITH_AES_128_CCM_8);
					CIPHER(TLS_RSA_WITH_AES_256_CCM_8);
					CIPHER(TLS_DHE_RSA_WITH_AES_128_CCM_8);
					CIPHER(TLS_DHE_RSA_WITH_AES_256_CCM_8);
					CIPHER(TLS_PSK_WITH_AES_128_CCM);
					CIPHER(TLS_PSK_WITH_AES_256_CCM);
					CIPHER(TLS_DHE_PSK_WITH_AES_128_CCM);
					CIPHER(TLS_DHE_PSK_WITH_AES_256_CCM);
					CIPHER(TLS_PSK_WITH_AES_128_CCM_8);
					CIPHER(TLS_PSK_WITH_AES_256_CCM_8);
					CIPHER(TLS_PSK_DHE_WITH_AES_128_CCM_8);
					CIPHER(TLS_PSK_DHE_WITH_AES_256_CCM_8);
					CIPHER(TLS_ECDHE_ECDSA_WITH_AES_128_CCM);
					CIPHER(TLS_ECDHE_ECDSA_WITH_AES_256_CCM);
					CIPHER(TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
					CIPHER(TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8);
					CIPHER(TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
					CIPHER(TLS_ECCPWD_WITH_AES_256_GCM_SHA384);
					CIPHER(TLS_ECCPWD_WITH_AES_128_CCM_SHA256);
					CIPHER(TLS_ECCPWD_WITH_AES_256_CCM_SHA384);
					CIPHER(TLS_SHA256_SHA256);
					CIPHER(TLS_SHA384_SHA384);
					CIPHER(TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC);
					CIPHER(TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC);
					CIPHER(TLS_GOSTR341112_256_WITH_28147_CNT_IMIT);
					CIPHER(TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L);
					CIPHER(TLS_GOSTR341112_256_WITH_MAGMA_MGM_L);
					CIPHER(TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S);
					CIPHER(TLS_GOSTR341112_256_WITH_MAGMA_MGM_S);
					CIPHER(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
					CIPHER(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
					CIPHER(TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
					CIPHER(TLS_PSK_WITH_CHACHA20_POLY1305_SHA256);
					CIPHER(TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256);
					CIPHER(TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256);
					CIPHER(TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256);
					CIPHER(TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256);
					CIPHER(TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384);
					CIPHER(TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256);
					CIPHER(TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256);
				}
				
				auto compressionMethod {"Unknown"};
				{
					if (serverHello->compressionMethod == CompressionMethod::NONE)
						compressionMethod = "None";
					else if (serverHello->compressionMethod == CompressionMethod::DEFLATE)
						compressionMethod = "Deflate";
				}

				fmt::print(FMT_STRING("  ServerHello\n   - Server Version: {}\n   - Random Bytes ({}):\n       {:.{}}\n   - Session Id ({}):\n       {:.{}}\n   - Cipher: {}\n   - Compression Method: {}\n"),
						   serverVersion,
						   serverHello->random.data.size(), randomBytesMemoryBuffer.data(), randomBytesMemoryBuffer.size(),
						   serverHello->sessionId.data.size(), sessionIdMemoryBuffer.data(), sessionIdMemoryBuffer.size(),
						   cipher, compressionMethod);
				if (!serverHello->extensions.empty()) {
					// TODO: list extension names and their data
					//fmt::print(FMT_STRING("\n   - Extensions: {}\n"));
				}
				#pragma endregion
			} else if (const auto certificate = std::get_if<Certificate>(&message)) {
				#pragma region Certificate
				fmt::print(FMT_STRING("  Certificate ({})\n"), certificate->certificates.size());
				for (const auto &certificateBytes : certificate->certificates)
					fmt::print(FMT_STRING("   - Certificate Data: {:p}-{:p} ({})\n"), certificateBytes.data(), certificateBytes.data() + certificateBytes.size(), certificateBytes.size());
				#pragma endregion
			} else if (const auto serverKeyExchange = std::get_if<ServerKeyExchange>(&message)) {
				#pragma region ServerKeyExchange
				auto curve {"Unknown"};
				{
					#define CURVE(X) if (serverKeyExchange->curve == NamedGroup::X) curve = #X  // NOLINT(cppcoreguidelines-macro-usage)

					CURVE(SECT163K1);
					CURVE(SECT163R1);
					CURVE(SECT163R2);
					CURVE(SECT193R1);
					CURVE(SECT193R2);
					CURVE(SECT233K1);
					CURVE(SECT233R1);
					CURVE(SECT239K1);
					CURVE(SECT283K1);
					CURVE(SECT283R1);
					CURVE(SECT409K1);
					CURVE(SECT409R1);
					CURVE(SECT571K1);
					CURVE(SECT571R1);
					CURVE(SECP160K1);
					CURVE(SECP160R1);
					CURVE(SECP160R2);
					CURVE(SECP192K1);
					CURVE(SECP192R1);
					CURVE(SECP224K1);
					CURVE(SECP224R1);
					CURVE(SECP256K1);
					CURVE(SECP256R1);
					CURVE(SECP384R1);
					CURVE(SECP521R1);
					CURVE(X25519);
					CURVE(X448);
					CURVE(FFDHE2048);
					CURVE(FFDHE3072);
					CURVE(FFDHE4096);
					CURVE(FFDHE6144);
					CURVE(FFDHE8192);
				}

				fmt::memory_buffer publicKeyMemoryBuffer {};
				for (std::size_t i {}; auto &&byte : serverKeyExchange->publicKey) {
					if (++i < serverKeyExchange->publicKey.size())
						if (i % 16 == 0)
							fmt::format_to(publicKeyMemoryBuffer, FMT_STRING("{:02X}\n       "), byte);
						else
							fmt::format_to(publicKeyMemoryBuffer, FMT_STRING("{:02X} "), byte);
					else
						fmt::format_to(publicKeyMemoryBuffer, FMT_STRING("{:02X}"), byte);
				}
				
				auto signatureScheme {"Unknown"};
				{
					#define SIGNATURE_SCHEME(X) if (serverKeyExchange->signatureScheme == SignatureScheme::X) signatureScheme = #X  // NOLINT(cppcoreguidelines-macro-usage)
					
					SIGNATURE_SCHEME(RSA_PKCS1_SHA256);
					SIGNATURE_SCHEME(RSA_PKCS1_SHA384);
					SIGNATURE_SCHEME(RSA_PKCS1_SHA512);
					SIGNATURE_SCHEME(ECDSA_SECP256R1_SHA256);
					SIGNATURE_SCHEME(ECDSA_SECP384R1_SHA384);
					SIGNATURE_SCHEME(ECDSA_SECP521R1_SHA512);
					SIGNATURE_SCHEME(RSA_PSS_RSAE_SHA256);
					SIGNATURE_SCHEME(RSA_PSS_RSAE_SHA384);
					SIGNATURE_SCHEME(RSA_PSS_RSAE_SHA512);
					SIGNATURE_SCHEME(ED25519);
					SIGNATURE_SCHEME(ED448);
					SIGNATURE_SCHEME(RSA_PSS_PSS_SHA256);
					SIGNATURE_SCHEME(RSA_PSS_PSS_SHA384);
					SIGNATURE_SCHEME(RSA_PSS_PSS_SHA512);
					SIGNATURE_SCHEME(RSA_PKCS_SHA1);
					SIGNATURE_SCHEME(ECDSA_SHA1);
				}

				fmt::memory_buffer signatureMemoryBuffer {};
				for (std::size_t i {}; auto &&byte : serverKeyExchange->signature) {
					if (++i < serverKeyExchange->signature.size())
						if (i % 16 == 0)
							fmt::format_to(signatureMemoryBuffer, FMT_STRING("{:02X}\n       "), byte);
						else
							fmt::format_to(signatureMemoryBuffer, FMT_STRING("{:02X} "), byte);
					else
						fmt::format_to(signatureMemoryBuffer, FMT_STRING("{:02X}"), byte);
				}
				
				fmt::print(FMT_STRING("  ServerKeyExchange\n   - Curve: {}\n   - Public Key ({}):\n       {:.{}}\n   - Signature Scheme: {}\n   - Signature ({}):\n       {:.{}}\n"),
						   curve,
						   serverKeyExchange->publicKey.size(), publicKeyMemoryBuffer.data(), publicKeyMemoryBuffer.size(),
						   signatureScheme,
						   serverKeyExchange->signature.size(), signatureMemoryBuffer.data(), signatureMemoryBuffer.size());
				#pragma endregion
			} else if (const auto certificateRequest = std::get_if<CertificateRequest>(&message)) {
				#pragma region CertificateRequest
				fmt::print(FMT_STRING("  Certificate Request\n"));

				fmt::memory_buffer certificateTypesMemoryBuffer {};
				for (std::size_t i {}; auto &&certificateType : certificateRequest->certificateTypes) {
					auto type {"Unknown"};
					{
						#define CLIENT_CERTIFICATE_TYPE(X) if (certificateType == ClientCertificateType::X) type = #X  // NOLINT(cppcoreguidelines-macro-usage)

						CLIENT_CERTIFICATE_TYPE(RSA_SIGN);
						CLIENT_CERTIFICATE_TYPE(DSS_SIGN);
						CLIENT_CERTIFICATE_TYPE(RSA_FIXED_DH);
						CLIENT_CERTIFICATE_TYPE(DSS_FIXED_DH);
						CLIENT_CERTIFICATE_TYPE(RSA_EPHEMERAL_DH);
						CLIENT_CERTIFICATE_TYPE(DSS_EPHEMERAL_DH);
						CLIENT_CERTIFICATE_TYPE(FORTEZZA_DMS);
						CLIENT_CERTIFICATE_TYPE(ECDSA_SIGN);
						CLIENT_CERTIFICATE_TYPE(RSA_FIXED_ECDH);
						CLIENT_CERTIFICATE_TYPE(ECDSA_FIXED_ECDH);
					}
					if (++i < certificateRequest->certificateTypes.size())
						fmt::format_to(certificateTypesMemoryBuffer, FMT_STRING("{}, "), type);
					else
						fmt::format_to(certificateTypesMemoryBuffer, FMT_STRING("{}"), type);
				}
				fmt::print(FMT_STRING("   - Certificate Types ({}): {:.{}}\n"),
						   certificateRequest->certificateTypes.size(), certificateTypesMemoryBuffer.data(), certificateTypesMemoryBuffer.size());

				fmt::memory_buffer signatureAlgorithmsMemoryBuffer {};
				for (std::size_t i {}; auto &&algorithm : certificateRequest->signatureAlgorithms) {
					auto hashAlgorithm {"Unknown"}, signatureAlgorithm {"Unknown"};
					{
						#define HASH_ALGORITHM(X) if (algorithm.hashAlgorithm == HashAlgorithm::X) hashAlgorithm = #X  // NOLINT(cppcoreguidelines-macro-usage)
						#define SIGNATURE_ALGORITHM(X) if (algorithm.signatureAlgorithm == SignatureAlgorithm::X) signatureAlgorithm = #X  // NOLINT(cppcoreguidelines-macro-usage)

						HASH_ALGORITHM(NONE);
						HASH_ALGORITHM(MD5);
						HASH_ALGORITHM(SHA1);
						HASH_ALGORITHM(SHA224);
						HASH_ALGORITHM(SHA256);
						HASH_ALGORITHM(SHA384);
						HASH_ALGORITHM(SHA512);

						SIGNATURE_ALGORITHM(ANONYMOUS);
						SIGNATURE_ALGORITHM(RSA);
						SIGNATURE_ALGORITHM(DSA);
						SIGNATURE_ALGORITHM(ECDSA);
					}

					if (++i < certificateRequest->signatureAlgorithms.size())
						fmt::format_to(signatureAlgorithmsMemoryBuffer, FMT_STRING("[{}, {}], "), hashAlgorithm, signatureAlgorithm);
					else
						fmt::format_to(signatureAlgorithmsMemoryBuffer, FMT_STRING("[{}, {}]"), hashAlgorithm, signatureAlgorithm);
				}
				fmt::print(FMT_STRING("   - Signature Algorithms ({}): {:.{}}\n"),
						   certificateRequest->signatureAlgorithms.size(), signatureAlgorithmsMemoryBuffer.data(), signatureAlgorithmsMemoryBuffer.size());

				for (const auto distinguishedName : certificateRequest->distinguishedNames)
					fmt::print(FMT_STRING("   - Distinguished Name: {:p}-{:p} ({})\n"),
							   distinguishedName.data(), distinguishedName.data() + distinguishedName.size(), distinguishedName.size());
				#pragma endregion
			} else if ([[maybe_unused]] const auto serverHelloDone = std::get_if<ServerHelloDone>(&message))
				fmt::print(FMT_STRING("  ServerHelloDone\n"));
			else if ([[maybe_unused]] const auto finished = std::get_if<Finished>(&message))
				fmt::print(FMT_STRING("  Finished\n"));
			else
				fmt::print(FMT_STRING("  Unhandled message, index: {}\n"), message.index());
		}
	}*/
	#pragma endregion
}
