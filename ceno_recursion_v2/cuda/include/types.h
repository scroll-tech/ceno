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
    Fp contribution[D_EF];
    Fp acc_in[D_EF];
    Fp acc_out[D_EF];
    Fp expected[D_EF];
} MainFinalClaimData;

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
    bool is_next_term;
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
