#include "Writer.hpp"

using namespace tls::stream;

tls::VectorType::difference_type Writer::write(const SpanType data) {
	const auto iterator = this->_data.insert(this->_data.cend(), data.data(), data.data() + data.size());
	return std::distance(this->_data.begin(), iterator);
}
tls::VectorType::difference_type Writer::write(const InitializerListType values) {
	const auto iterator = this->_data.insert(this->_data.cend(), values.begin(), values.end());
	return std::distance(this->_data.begin(), iterator);
}
tls::VectorType::difference_type Writer::write(const std::string_view string) {
	const auto iterator = this->_data.insert(this->_data.cend(), string.cbegin(), string.cend());
	return std::distance(this->_data.begin(), iterator);
}

tls::VectorType::pointer Writer::data() noexcept {
	return this->_data.data();
}
tls::VectorType::const_pointer Writer::data() const noexcept {
	return this->_data.data();
}
tls::VectorType::size_type Writer::size() const noexcept {
	return this->_data.size();
}
void Writer::reserve(const VectorType::size_type capacity) {
	this->_data.reserve(capacity);
}

tls::SpanType Writer::subspan(const SpanType::size_type offset, const SpanType::size_type count) const noexcept {
	return static_cast<SpanType>(*this).subspan(offset, count);
}

Writer Writer::operator +(const Writer &byteStream) const {
	Writer newStream {};
	newStream._data.reserve(this->size() + byteStream.size());
	newStream._data.insert(newStream._data.cend(), this->_data.cbegin(), this->_data.cend());
	newStream._data.insert(newStream._data.cend(), byteStream._data.cbegin(), byteStream._data.cend());

	return newStream;
}
Writer Writer::operator +(const VectorType &byteStream) const {
	Writer newStream {};
	newStream._data.reserve(this->size() + byteStream.size());
	newStream._data.insert(newStream._data.cend(), this->_data.cbegin(), this->_data.cend());
	newStream._data.insert(newStream._data.cend(), byteStream.cbegin(), byteStream.cend());

	return newStream;
}
Writer Writer::operator +(const SpanType byteStream) const {
	Writer newStream {};
	newStream._data.reserve(this->size() + byteStream.size());
	newStream._data.insert(newStream._data.cend(), this->_data.cbegin(), this->_data.cend());
	newStream._data.insert(newStream._data.cend(), byteStream.begin(), byteStream.end());

	return newStream;
}

Writer &Writer::operator +=(const Writer &byteStream) {
	this->_data.insert(this->_data.cend(), byteStream._data.cbegin(), byteStream._data.cend());
	return *this;
}
Writer &Writer::operator +=(const VectorType &byteStream) {
	this->_data.insert(this->_data.cend(), byteStream.cbegin(), byteStream.cend());
	return *this;
}
Writer &Writer::operator +=(const SpanType byteStream) {
	this->_data.insert(this->_data.cend(), byteStream.begin(), byteStream.end());
	return *this;
}

Writer::operator tls::SpanType() const noexcept {
	return {this->data(), this->size()};
}
