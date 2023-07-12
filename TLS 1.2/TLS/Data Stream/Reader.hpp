#pragma once

#include "Stream.hpp"
#include "Byte Order.hpp"

namespace tls::stream {
	struct Reader {
		Reader() = default;
		Reader(const UnderlyingDataType *data, SpanType::size_type size) noexcept;
		Reader(SpanType data) noexcept;

		template<detail::Integral T>
		[[nodiscard]] T read(ByteOrder &&byteOrder = ByteOrder::NETWORK_ORDER) noexcept {
			return this->read<T>(this->_offset, std::move(byteOrder));
		}
		template<class T>
		requires (std::is_same_v<T, UnsignedInt24> || std::is_same_v<T, Int24>)
		[[nodiscard]] decltype(T::value) read(ByteOrder &&byteOrder = ByteOrder::NETWORK_ORDER) noexcept {
			return this->read<T>(this->_offset, std::move(byteOrder));
		}
		template<SizeType Size>
		[[nodiscard]] Array<Size> read() noexcept {
			return this->read<Size>(this->_offset);
		}
		[[nodiscard]] SpanType read(SpanType::size_type length) noexcept;
		Reader &advance(DifferenceType distance) noexcept;

		template<detail::Integral T>
		[[nodiscard]] T read(DifferenceType &offset, ByteOrder &&byteOrder = ByteOrder::NETWORK_ORDER) const noexcept {  // NOLINT(clang-diagnostic-shadow)
			if (offset < 0 || offset + sizeof(T) > this->_data.size_bytes())
				return {};

			T value = *reinterpret_cast<const T*>(this->_data.data() + offset);
			offset += sizeof(T);

			if (byteOrder == ByteOrder::LITTLE_ENDIAN)
				return value;

			// Big endian
			if constexpr (sizeof(T) == sizeof(std::uint64_t))
				return _byteswap_uint64(value);
			if constexpr (sizeof(T) == sizeof(std::uint32_t))
				return _byteswap_ulong(value);
			if constexpr (sizeof(T) == sizeof(std::uint16_t))
				return _byteswap_ushort(value);
			return value;
		}
		template<class T>
		requires (std::is_same_v<T, UnsignedInt24> || std::is_same_v<T, Int24>)
		[[nodiscard]] decltype(T::value) read(DifferenceType &offset, ByteOrder &&byteOrder = ByteOrder::NETWORK_ORDER) noexcept {
			using UnderlyingType = decltype(T::value);

			if (offset < 0 || offset + T::sizeInBytes >= this->_data.size_bytes())
				return {};
			
			const auto data = this->read<3>(offset);
			UnderlyingType value {};
			if (byteOrder == ByteOrder::BIG_ENDIAN)
				value = data[2] | data[1] << 8 | data[0] << 16;
			else if (byteOrder == ByteOrder::LITTLE_ENDIAN)
				value = data[0] | data[1] << 8 | data[2] << 16;
			if constexpr (std::is_same_v<UnderlyingType, Int24>) {
				if (byteOrder == ByteOrder::BIG_ENDIAN && data[0] & 0x80)
					value = 0xFF << 24 | value;
				else if (byteOrder == ByteOrder::LITTLE_ENDIAN && data[2] & 0x80)
					value = 0xFF << 24 | value;
			}
			
			return value;
		}
		template<SizeType Size>
		[[nodiscard]] Array<Size> read(DifferenceType &offset) const noexcept {  // NOLINT(clang-diagnostic-shadow)
			if (offset < 0 || offset + Size >= this->_data.size_bytes())
				return {};

			const auto data = this->_data.data() + offset;  // NOLINT(clang-diagnostic-shadow)
			offset += Size;

			Array<Size> result {};
			std::copy_n(data, Size, result.data());

			return result;
		}
		[[nodiscard]] SpanType read(DifferenceType &offset, SpanType::size_type length) const noexcept;

		[[nodiscard]] SpanType data() const noexcept;
		[[nodiscard]] SpanType::size_type size() const noexcept;
		[[nodiscard]] DifferenceType offset() const noexcept;
	private:
		SpanType       _data {};
		DifferenceType _offset {};
	};
}
