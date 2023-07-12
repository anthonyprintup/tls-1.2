#pragma once

#include <cstddef>

namespace tls {
	template<std::size_t N>
	concept IsDivisibleBy8 = N % 8 == 0;

	template<std::size_t N, std::size_t V>
	concept HigherThanOrEqual = N >= V;

	template<std::size_t N, std::size_t V>
	concept LowerThanOrEqual = N <= V;

	template<std::size_t SizeInBits>
	requires IsDivisibleBy8<SizeInBits>
	struct BitsToBytes {
		static constexpr std::size_t size {SizeInBits / 8};
	};
}
