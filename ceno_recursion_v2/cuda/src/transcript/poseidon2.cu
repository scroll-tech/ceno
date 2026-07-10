#include "fp.h"
#include "launcher.cuh"
#include "poseidon2-air/columns.cuh"
#include "poseidon2-air/params.cuh"
#include "poseidon2-air/tracegen.cuh"
#include "primitives/trace_access.h"
#include "types.h"

#include <cassert>
#include <cstddef>
#include <cstdint>

template <size_t WIDTH, typename PoseidonParams>
__global__ void transcript_poseidon2_tracegen(
    Fp *d_trace,
    size_t trace_height,
    size_t trace_width,
    const Poseidon2Record *d_records,
    size_t num_records
) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    using Poseidon2Row = poseidon2::Poseidon2Row<
        WIDTH,
        PoseidonParams::SBOX_DEGREE,
        PoseidonParams::SBOX_REGS,
        PoseidonParams::HALF_FULL_ROUNDS,
        PoseidonParams::PARTIAL_ROUNDS>;

    if (idx >= trace_height) {
        return;
    }

    Poseidon2Row row(d_trace + idx, trace_height);
    if (idx < num_records) {
        const Poseidon2Record &record = d_records[idx];
        RowSlice state(const_cast<Fp *>(record.state), 1);
        poseidon2::generate_trace_row_for_perm(row, state);
        d_trace[idx + Poseidon2Row::get_total_size() * trace_height] = record.count.perm;
        d_trace[idx + (Poseidon2Row::get_total_size() + 1) * trace_height] =
            record.count.compress;
    } else {
        Fp dummy[Poseidon2Row::get_total_size()] = {0};
        RowSlice dummy_row(dummy, 1);
        poseidon2::generate_trace_row_for_perm(row, dummy_row);
        d_trace[idx + Poseidon2Row::get_total_size() * trace_height] = 0;
        d_trace[idx + (Poseidon2Row::get_total_size() + 1) * trace_height] = 0;
    }

#ifdef CUDA_DEBUG
    assert(Poseidon2Row::get_total_size() + 2 == trace_width);
#else
    (void)trace_width;
#endif
}

extern "C" int _transcript_poseidon2_tracegen(
    Fp *d_trace,
    size_t height,
    size_t width,
    const Poseidon2Record *d_records,
    size_t num_records,
    cudaStream_t stream
) {
    assert((height & (height - 1)) == 0);
    auto [grid, block] = kernel_launch_params(height);
    transcript_poseidon2_tracegen<16, Poseidon2ParamsS1><<<grid, block, 0, stream>>>(
        d_trace, height, width, d_records, num_records
    );
    return CHECK_KERNEL();
}
