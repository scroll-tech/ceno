#pragma once

#include "fp.h"

#include <cstddef>
#include <cstdint>

constexpr size_t D_EF = 4;
constexpr size_t DIGEST_SIZE = 8;
typedef Fp Digest[DIGEST_SIZE];

typedef struct {
    size_t air_idx;
    uint8_t log_height;
} TraceHeight;

typedef struct {
    size_t cached_idx;
    size_t total_interactions;
    size_t num_air_id_lookups;
} TraceMetadata;

typedef struct {
    size_t air_idx;
    size_t air_num_pvs;
    size_t num_airs;
    size_t pv_idx;
    Fp value;
} PublicValueData;

typedef struct {
    size_t num_cached;
    size_t num_interactions_per_row;
    size_t total_width;
    bool has_preprocessed;
    bool need_rot;
} AirData;

typedef struct {
    size_t proof_idx;
    size_t idx;
    size_t eval_idx;
    size_t tidx;
    Fp value[D_EF];
    size_t lookup_count;
} MainEvalData;

typedef struct {
    size_t proof_idx;
    size_t idx;
    size_t round_idx;
    Fp global_value[D_EF];
    Fp tower_value[D_EF];
    Fp eq_in[D_EF];
    Fp eq_out[D_EF];
} MainTowerPointEqData;

typedef struct {
    size_t proof_idx;
    size_t idx;
    size_t row_idx;
    size_t node_idx;
    size_t eval_idx;
    bool has_eval_factor;
    size_t instance_idx;
    size_t challenge_idx;
    size_t global_round_idx;
    bool has_global_factor;
    bool is_wit;
    bool is_const;
    bool is_instance;
    bool is_challenge;
    bool is_add;
    bool is_sub;
    bool is_neg;
    bool is_mul;
    bool is_fold;
    bool is_tail;
    size_t constraint_idx;
    Fp alpha[D_EF];
    Fp arg0[D_EF];
    Fp arg1[D_EF];
    Fp value[D_EF];
    Fp chip_acc_in[D_EF];
    Fp chip_acc_out[D_EF];
    bool is_last_chip_step;
} MainFrontloadTermData;

typedef struct {
    size_t proof_idx;
    size_t round_idx;
    size_t sumcheck_idx;
    size_t commitment_kind;
    size_t term_idx;
    size_t step_idx;
    size_t robp_idx;
    bool is_first;
    bool is_last;
    bool is_first_step;
    bool is_last_step;
    bool term_is_last;
    Fp eq_col[D_EF];
    size_t t_lo;
    size_t t_hi;
    bool c_bit;
    bool d_bit;
    size_t bit_pow2;
    size_t c_acc_in;
    size_t c_acc_out;
    size_t d_acc_in;
    size_t d_acc_out;
    Fp rho_star_c[D_EF];
    Fp rho_star_d[D_EF];
    Fp factor[D_EF];
    Fp term_acc_in[D_EF];
    Fp term_acc_out[D_EF];
    Fp q_acc_in[D_EF];
    Fp q_acc_out[D_EF];
} PcsJaggedAssistQData;

typedef struct {
    size_t proof_idx;
    bool is_proof_start;
    size_t tidx;
    bool is_sample;
    Fp mask[8];
    Fp prev_state[16];
    Fp post_state[16];
    bool is_fork_start;
    bool is_fork;
    size_t fork_id;
} TranscriptRowData;

typedef struct {
    size_t proof_idx;
    size_t idx;
    size_t fork_id;
    size_t layer_idx;
    bool is_first_idx;
    bool is_first_layer;
    bool is_first_round;
    bool is_dummy;
    bool is_last_layer;
    size_t round;
    size_t tidx;
    Fp ev1[D_EF];
    Fp ev2[D_EF];
    Fp ev3[D_EF];
    Fp claim_in[D_EF];
    Fp claim_out[D_EF];
    Fp prev_challenge[D_EF];
    Fp challenge[D_EF];
    Fp eq_in[D_EF];
    Fp eq_out[D_EF];
} TowerSumcheckData;

typedef struct {
    size_t proof_idx;
    size_t idx;
    size_t tower_idx;
    size_t air_idx;
    size_t selector_idx;
    size_t eval_idx;
    size_t kind;
    size_t source_kind;
    bool is_whole;
    bool is_prefix;
    bool is_ordered_sparse;
    bool is_quark_binary_tree_less_than;
    size_t ctx_offset;
    size_t ctx_num_instances;
    size_t ctx_num_vars;
    size_t ordered_sparse_num_vars;
    size_t num_sparse_indices;
    size_t step_kind;
    size_t step_idx;
    bool is_shape_step;
    bool is_eq_product_step;
    bool is_sparse_index_step;
    bool is_accumulate_step;
    bool is_final_step;
    bool is_multiply_step;
    bool is_quark_step;
    bool is_eq_lte_step;
    bool is_first_eq_lte_step;
    bool is_last_eq_lte_step;
    bool eq_lte_output_to_value;
    bool eq_lte_output_to_acc_in;
    bool eq_lte_output_to_factor;
    bool eq_lte_output_to_neg_factor;
    bool eq_lte_value_is_zero;
    bool is_first_quark_step;
    bool is_last_quark_step;
    bool carry_accumulator;
    size_t round_idx;
    size_t sparse_pos;
    size_t sparse_index;
    size_t sparse_index_bits_value;
    bool point_active;
    Fp lhs_point[D_EF];
    Fp rhs_point[D_EF];
    Fp factor[D_EF];
    Fp acc_in[D_EF];
    Fp acc_out[D_EF];
    Fp aux[D_EF];
    Fp aux2[D_EF];
    Fp aux3[D_EF];
    Fp value[D_EF];
} MainSelectorFormulaData;
