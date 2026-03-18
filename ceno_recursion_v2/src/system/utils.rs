use openvm_stark_backend::{
    SystemParams, WhirConfig, WhirParams, WhirProximityStrategy,
    interaction::LogUpSecurityParameters,
};

fn test_whir_config_small(
    log_blowup: usize,
    log_stacked_height: usize,
    k_whir: usize,
    log_final_poly_len: usize,
) -> WhirConfig {
    let params = WhirParams {
        k: k_whir,
        log_final_poly_len,
        query_phase_pow_bits: 1,
        folding_pow_bits: 2,
        mu_pow_bits: 3,
        proximity: WhirProximityStrategy::SplitUniqueList {
            m: 3,
            list_start_round: 1,
        },
    };
    let security_bits = 5;
    WhirConfig::new(log_blowup, log_stacked_height, params, security_bits)
}

/// Trace heights cannot exceed `2^{l_skip + n_stack}` and stacked cells cannot exceed
/// `w_stack * 2^{l_skip + n_stack}` when using these system params.
fn test_system_params_small(l_skip: usize, n_stack: usize, k_whir: usize) -> SystemParams {
    let log_final_poly_len = (n_stack + l_skip) % k_whir;
    test_system_params_small_with_poly_len(l_skip, n_stack, k_whir, log_final_poly_len, 5)
}

pub fn test_system_params_zero_pow(l_skip: usize, n_stack: usize, k_whir: usize) -> SystemParams {
    let mut params = test_system_params_small(l_skip, n_stack, k_whir);
    params.whir.mu_pow_bits = 0;
    params.whir.folding_pow_bits = 0;
    params.whir.query_phase_pow_bits = 0;
    params
}

fn test_system_params_small_with_poly_len(
    l_skip: usize,
    n_stack: usize,
    k_whir: usize,
    log_final_poly_len: usize,
    max_constraint_degree: usize,
) -> SystemParams {
    assert!(log_final_poly_len < l_skip + n_stack);
    let log_blowup = 1;
    SystemParams {
        l_skip,
        n_stack,
        w_stack: 1 << 12,
        log_blowup,
        whir: test_whir_config_small(log_blowup, l_skip + n_stack, k_whir, log_final_poly_len),
        logup: LogUpSecurityParameters {
            max_interaction_count: 1 << 30,
            log_max_message_length: 7,
            pow_bits: 2,
        },
        max_constraint_degree,
    }
}
