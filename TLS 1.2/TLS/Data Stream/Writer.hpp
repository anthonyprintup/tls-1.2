#pragma once

#include "Stream.hpp"
#include "Byte Order.hpp"
#include "../Common Types.hpp"

#include <string_view>

namespace tls::stream {
	struct Writer {
		template<detail::Integral T>
		VectorType::difference_type write(const T value = {}, ByteOrder &&byteOrder = ByteOrder::NETWORK_ORDER) {
			const auto first = reinterpret_cast<UnderlyingDataType*>(const_cast<T*>(&value));
			const auto last = reinterpret_cast<UnderlyingDataType*>(const_cast<T*>(&value)) + sizeof(T);

			VectorType::const_iterator iterator {};
			if (byteOrder == ByteOrder::BIG_ENDIAN)
				iterator = this->_data.insert(this->_data.cend(), std::make_reverse_iterator(last), std::make_reverse_iterator(first));
			else if (byteOrder == ByteOrder::LITTLE_ENDIAN)
				iterator = this->_data.insert(this->_data.cend(), first, last);
			return std::distance(this->_data.cbegin(), iterator);
		}
		template<class T>
		requires (std::is_same_v<T, UnsignedInt24> || std::is_same_v<T, Int24>)
		VectorType::difference_type write(const decltype(T::value) value = {}, ByteOrder &&byteOrder = ByteOrder::NETWORK_ORDER) {
			using UnderlyingType = decltype(T::value);
			if (value == 0)
				return this->write<3>();

			ArrayType<3> data {};
			for (std::size_t i {}; i < 3; ++i)
				if (byteOrder == ByteOrder::BIG_ENDIAN)
					data[i] = reinterpret_cast<UnderlyingDataType*>(const_cast<UnderlyingType*>(&value))[sizeof(UnderlyingType) - sizeof(UnderlyingDataType) * 2 - i];
				else if (byteOrder == ByteOrder::LITTLE_ENDIAN)
					data[i] = reinterpret_cast<UnderlyingDataType*>(const_cast<UnderlyingType*>(&value))[i];

			return this->write(data);
		}
		VectorType::difference_type write(SpanType data);
		template<SizeType Size>
		VectorType::difference_type write(const ArrayType<Size> values = {}) {
			const auto iterator = this->_data.insert(this->_data.cend(), values.cbegin(), values.cend());
			return std::distance(this->_data.begin(), iterator);
		}
		VectorType::difference_type write(InitializerListType values);
		VectorType::difference_type write(std::string_view string);

		[[nodiscard]] VectorType::pointer data() noexcept;
		[[nodiscard]] VectorType::const_pointer data() const noexcept;
		[[nodiscard]] VectorType::size_type size() const noexcept;
		void reserve(VectorType::size_type capacity);

		template<SizeType Size>
		[[nodiscard]] Array<Size> subarray(const SpanType::size_type offset) const noexcept {
			return this->subspan(offset, Size);
		}
		[[nodiscard]] SpanType subspan(SpanType::size_type offset, SpanType::size_type count = SpanType::extent) const noexcept;

		Writer operator +(const Writer &byteStream) const;
		Writer operator +(const VectorType &byteStream) const;
		Writer operator +(SpanType byteStream) const;
		Writer &operator +=(const Writer &byteStream);
		Writer &operator +=(const VectorType &byteStream);
		Writer &operator +=(SpanType byteStream);

		// ReSharper disable once CppNonExplicitConversionOperator
		operator SpanType() const noexcept;
	private:
		VectorType _data {};
	};
}
