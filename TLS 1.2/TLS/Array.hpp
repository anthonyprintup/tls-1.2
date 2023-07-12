#pragma once

#include <span>

#include "Concepts.hpp"
#include "Common Types.hpp"

namespace tls {
	template<std::size_t BaseSize>
	struct Array: ArrayType<BaseSize> {
		Array() = default;
		template<class... Bytes>
		explicit constexpr Array(Bytes &&...bytes) noexcept:
			ArrayType<BaseSize> {{
				static_cast<UnderlyingDataType>(std::forward<Bytes>(bytes))...
			}} {}
		// ReSharper disable once CppNonExplicitConvertingConstructor
		Array(const SpanType data) noexcept {
			*this = data;
		}
		template<std::size_t Size>
		constexpr Array(const Array<Size> &data) noexcept {
			*this = data;
		}

		[[nodiscard]] SpanType subspan(const SpanType::size_type offset, const SpanType::size_type count = SpanType::extent) const noexcept {
			if (offset + count > this->size())
				return {};
			return {this->data() + offset, count};
		}
		[[nodiscard]] MutableSpanType subspan(const SpanType::size_type offset, const SpanType::size_type count = SpanType::extent) noexcept {
			if (offset + count > this->size())
				return {};
			return {this->data() + offset, count};
		}

		template<std::size_t Count>
		requires HigherThanOrEqual<BaseSize, Count>
		[[nodiscard]] auto subarray(const SpanType::size_type offset = {}) const noexcept {
			Array<Count> buffer {};
			if (offset + Count > this->size())
				return buffer;

			std::memcpy(buffer.data(), this->data() + offset, Count);
			return buffer;
		}

		void clear() noexcept {
			this->fill(0);
		}
		
		template<std::size_t Size>
		[[nodiscard]] auto operator +(const Array<Size> &data) const noexcept {
			Array<BaseSize + Size> buffer {};
			std::memcpy(buffer.data(), this->data(), this->size());
			std::memcpy(buffer.data() + this->size(), data.data(), data.size());

			return buffer;
		}
		template<std::size_t Size>
		[[nodiscard]] auto operator +(Array<Size> &&data) const noexcept {
			Array<BaseSize + Size> buffer {};
			std::memcpy(buffer.data(), this->data(), this->size());
			std::memcpy(buffer.data() + this->size(), data.data(), data.size());

			return buffer;
		}
		template<std::size_t Size>
		auto &operator =(const Array<Size> &data) noexcept {
			constexpr auto size = BaseSize >= Size ? Size : BaseSize;
			std::memcpy(this->data(), data.data(), size);
			return *this;
		}
		auto &operator =(const SpanType data) noexcept {
			const auto size = BaseSize >= data.size() ? BaseSize : data.size();
			std::memcpy(this->data(), data.data(), size);
			return *this;
		}
		
		[[nodiscard]] bool operator ==(const Array<BaseSize> &data) const noexcept {
			return std::memcmp(this->data(), data.data(), this->size()) == 0;
		}
		template<std::size_t Size>
		requires LowerThanOrEqual<Size, BaseSize>
		[[nodiscard]] bool operator ==(const Array<Size> &data) const noexcept {
			return std::memcmp(this->data(), data.data(), this->size()) == 0;
		}
		[[nodiscard]] bool operator ==(const SpanType data) const noexcept {
			if (data.size() > this->size())
				return false;
			return std::memcmp(this->data(), data.data(), std::min(this->size(), data.size())) == 0;
		}

		// ReSharper disable once CppNonExplicitConversionOperator
		operator ArrayType<BaseSize>() const noexcept {
			return *this;
		}
	};

	template<std::size_t SizeInBits>
	using BitArray = Array<BitsToBytes<SizeInBits>::size>;
}
