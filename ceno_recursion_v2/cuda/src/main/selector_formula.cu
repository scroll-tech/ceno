#include "fp.h"
#include "launcher.cuh"
#include "primitives/trace_access.h"
#include "types.h"

#include <cassert>
#include <cstddef>
#include <cstdint>

template <typename T> struct MainSelectorFormulaCols {
    T is_enabled;
    T proof_idx;
    T idx;
    T tower_idx;
    T air_idx;
    T selector_idx;
    T eval_idx;
    T kind;
    T source_kind;
    T is_whole;
    T is_prefix;
    T is_ordered_sparse;
    T is_quark_binary_tree_less_than;
    T ctx_offset;
    T ctx_num_instances;
    T ctx_num_vars;
    T ordered_sparse_num_vars;
    T num_sparse_indices;
    T step_kind;
    T step_idx;
    T is_shape_step;
    T is_eq_product_step;
    T is_sparse_index_step;
    T is_accumulate_step;
    T is_final_step;
    T is_multiply_step;
    T is_quark_step;
    T is_eq_lte_step;
    T is_first_eq_lte_step;
    T is_last_eq_lte_step;
    T eq_lte_output_to_value;
    T eq_lte_output_to_acc_in;
    T eq_lte_output_to_factor;
    T eq_lte_output_to_neg_factor;
    T eq_lte_value_is_zero;
    T is_first_quark_step;
    T is_last_quark_step;
    T carry_accumulator;
    T round_idx;
    T sparse_pos;
    T sparse_index;
    T sparse_index_bits_value;
    T point_active;
    T lhs_point[D_EF];
    T rhs_point[D_EF];
    T factor[D_EF];
    T acc_in[D_EF];
    T acc_out[D_EF];
    T aux[D_EF];
    T aux2[D_EF];
    T aux3[D_EF];
    T value[D_EF];
};

__global__ void main_selector_formula_tracegen(
    Fp *trace,
    size_t height,
    const MainSelectorFormulaData *records,
    size_t num_records
) {
    uint32_t row_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (row_idx >= height) {
        return;
    }

    RowSlice row(trace + row_idx, height);
    if (row_idx < num_records) {
        const MainSelectorFormulaData &record = records[row_idx];
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_enabled, Fp::one());
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, proof_idx, record.proof_idx);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, idx, record.idx);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, tower_idx, record.tower_idx);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, air_idx, record.air_idx);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, selector_idx, record.selector_idx);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, eval_idx, record.eval_idx);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, kind, record.kind);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, source_kind, record.source_kind);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_whole, record.is_whole);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_prefix, record.is_prefix);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_ordered_sparse, record.is_ordered_sparse);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_quark_binary_tree_less_than, record.is_quark_binary_tree_less_than);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, ctx_offset, record.ctx_offset);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, ctx_num_instances, record.ctx_num_instances);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, ctx_num_vars, record.ctx_num_vars);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, ordered_sparse_num_vars, record.ordered_sparse_num_vars);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, num_sparse_indices, record.num_sparse_indices);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, step_kind, record.step_kind);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, step_idx, record.step_idx);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_shape_step, record.is_shape_step);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_eq_product_step, record.is_eq_product_step);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_sparse_index_step, record.is_sparse_index_step);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_accumulate_step, record.is_accumulate_step);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_final_step, record.is_final_step);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_multiply_step, record.is_multiply_step);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_quark_step, record.is_quark_step);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_eq_lte_step, record.is_eq_lte_step);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_first_eq_lte_step, record.is_first_eq_lte_step);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_last_eq_lte_step, record.is_last_eq_lte_step);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, eq_lte_output_to_value, record.eq_lte_output_to_value);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, eq_lte_output_to_acc_in, record.eq_lte_output_to_acc_in);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, eq_lte_output_to_factor, record.eq_lte_output_to_factor);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, eq_lte_output_to_neg_factor, record.eq_lte_output_to_neg_factor);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, eq_lte_value_is_zero, record.eq_lte_value_is_zero);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_first_quark_step, record.is_first_quark_step);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, is_last_quark_step, record.is_last_quark_step);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, carry_accumulator, record.carry_accumulator);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, round_idx, record.round_idx);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, sparse_pos, record.sparse_pos);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, sparse_index, record.sparse_index);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, sparse_index_bits_value, record.sparse_index_bits_value);
        COL_WRITE_VALUE(row, MainSelectorFormulaCols, point_active, record.point_active);
        COL_WRITE_ARRAY(row, MainSelectorFormulaCols, lhs_point, record.lhs_point);
        COL_WRITE_ARRAY(row, MainSelectorFormulaCols, rhs_point, record.rhs_point);
        COL_WRITE_ARRAY(row, MainSelectorFormulaCols, factor, record.factor);
        COL_WRITE_ARRAY(row, MainSelectorFormulaCols, acc_in, record.acc_in);
        COL_WRITE_ARRAY(row, MainSelectorFormulaCols, acc_out, record.acc_out);
        COL_WRITE_ARRAY(row, MainSelectorFormulaCols, aux, record.aux);
        COL_WRITE_ARRAY(row, MainSelectorFormulaCols, aux2, record.aux2);
        COL_WRITE_ARRAY(row, MainSelectorFormulaCols, aux3, record.aux3);
        COL_WRITE_ARRAY(row, MainSelectorFormulaCols, value, record.value);
    } else {
        row.fill_zero(0, sizeof(MainSelectorFormulaCols<uint8_t>));
    }
}

extern "C" int _main_selector_formula_tracegen(
    Fp *d_trace,
    size_t height,
    const MainSelectorFormulaData *d_records,
    size_t num_records,
    cudaStream_t stream
) {
    assert((height & (height - 1)) == 0);
    auto [grid, block] = kernel_launch_params(height, 128);
    main_selector_formula_tracegen<<<grid, block, 0, stream>>>(
        d_trace,
        height,
        d_records,
        num_records
    );
    return CHECK_KERNEL();
}
