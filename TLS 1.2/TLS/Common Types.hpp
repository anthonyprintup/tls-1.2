#pragma once

#include <cstdint>
#include <span>
#include <array>
#include <vector>

namespace tls {
	using UnderlyingDataType = std::uint8_t;
	static_assert(sizeof(UnderlyingDataType) == 1, "Size of the UnderlyingDataType should be 1, to avoid pointer arithmetic issues.");
	
	using SpanType = std::span<const UnderlyingDataType>;
	using MutableSpanType = std::span<UnderlyingDataType>;
	template<std::size_t Size>
	using ArrayType = std::array<UnderlyingDataType, Size>;
	using InitializerListType = std::initializer_list<UnderlyingDataType>;
	using VectorType          = std::vector<UnderlyingDataType>;
}
