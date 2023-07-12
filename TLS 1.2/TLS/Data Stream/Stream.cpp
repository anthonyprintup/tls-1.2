#include "Stream.hpp"

using namespace tls::stream;

UnsignedInt24::operator std::uint32_t() const noexcept {
	return this->value;
}
UnsignedInt24::operator std::size_t() const noexcept {
	return this->value;
}

Int24::operator std::int32_t() const noexcept {
	return this->value;
}
Int24::operator std::size_t() const noexcept {
	return this->value;
}
