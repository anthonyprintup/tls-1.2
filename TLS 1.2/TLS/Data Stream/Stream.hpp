#pragma once

#include <cstdint>
#include <vector>

#include "../Array.hpp"

namespace tls::stream {
	namespace detail {
		template<class T>
		concept Integral = std::is_integral_v<T>;
	}

	using SizeType = std::size_t;
	struct UnsignedInt24 {
		static constexpr std::size_t sizeInBytes {3};
		
		std::uint32_t value {};
		operator std::uint32_t() const noexcept;
		operator std::size_t() const noexcept;
	};
	struct Int24 {
		static constexpr std::size_t sizeInBytes {3};
		
		std::int32_t value {};
		operator std::int32_t() const noexcept;
		operator std::size_t() const noexcept;
	};
	
	using DifferenceType = VectorType::difference_type;
}
