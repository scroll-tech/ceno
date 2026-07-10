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
