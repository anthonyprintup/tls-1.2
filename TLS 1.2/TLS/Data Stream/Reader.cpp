#include "Reader.hpp"

using namespace tls::stream;

Reader::Reader(const UnderlyingDataType *data, const SizeType size) noexcept:
	_data {data, size} {}

Reader::Reader(const SpanType data) noexcept:
	_data {data}  {}

tls::SpanType Reader::read(const SpanType::size_type length) noexcept {
	return this->read(this->_offset, length);
}

Reader &Reader::advance(const DifferenceType distance) noexcept{
	this->_offset += distance;
	return *this;
}

tls::SpanType Reader::read(DifferenceType &offset, const SpanType::size_type length) const noexcept {  // NOLINT(clang-diagnostic-shadow)
	if (offset < 0 || offset + length > this->_data.size_bytes())
		return {};

	const auto data = this->_data.data() + offset;  // NOLINT(clang-diagnostic-shadow)
	offset += length;

	return {data, length};
}

tls::SpanType Reader::data() const noexcept {
	return this->_data;
}

tls::SpanType::size_type Reader::size() const noexcept {
	return this->_data.size();
}

DifferenceType Reader::offset() const noexcept {
	return this->_offset;
}
