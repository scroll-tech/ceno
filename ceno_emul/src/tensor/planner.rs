//! Bounded streaming and fusion planning for statically-shaped Llama chips.
//!
//! This module is deliberately independent of CUDA.  It turns an observed GPU
//! capability into explicit buffer and shard limits which the host and device
//! implementations can both validate.  It never assumes that the model is
//! resident on the device.

use anyhow::{Result, ensure};

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuClass {
    Rtx4090,
    Rtx5070Ti,
    Rtx5090,
    Conservative,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuCapability {
    pub sm: u16,
    pub vram_bytes: u64,
}

impl GpuCapability {
    pub const RTX4090: Self = Self {
        sm: 89,
        vram_bytes: 24 * GIB,
    };
    pub const RTX5070_TI: Self = Self {
        sm: 120,
        vram_bytes: 16 * GIB,
    };
    pub const RTX5090: Self = Self {
        sm: 120,
        vram_bytes: 32 * GIB,
    };

    pub fn class(self) -> GpuClass {
        match (self.sm, self.vram_bytes) {
            (89, bytes) if bytes >= 23 * GIB => GpuClass::Rtx4090,
            (120, bytes) if bytes >= 31 * GIB => GpuClass::Rtx5090,
            (120, bytes) if bytes >= 15 * GIB => GpuClass::Rtx5070Ti,
            _ => GpuClass::Conservative,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TensorStreamingRequest {
    /// Authenticated quantized bytes consumed during one proof.
    pub weight_bytes: u64,
    /// Largest guest-visible boundary returned to the host.
    pub boundary_bytes: u64,
    /// Bytes used by one field-expanded weight byte in the active tile.
    pub lift_bytes_per_weight_byte: u8,
    /// External Ceno shard limit. The planner may reduce, never increase it.
    pub max_cell_per_shard: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TensorStreamingPlan {
    pub class: GpuClass,
    pub tile_bytes: u64,
    pub host_buffer_count: u8,
    pub device_buffer_count: u8,
    pub host_buffer_bytes: u64,
    pub device_buffer_bytes: u64,
    pub reserved_vram_bytes: u64,
    pub max_cell_per_shard: u64,
    pub h2d_bytes: u64,
    pub d2h_bytes: u64,
    pub full_model_resident: bool,
}

/// Select two reusable host/device buffers while reserving at least half of
/// VRAM for Ceno witness matrices, PCS and tower work.
pub fn plan_streaming(
    capability: GpuCapability,
    request: TensorStreamingRequest,
) -> Result<TensorStreamingPlan> {
    ensure!(capability.vram_bytes >= 4 * GIB, "GPU VRAM below 4 GiB");
    ensure!(request.weight_bytes > 0, "weight stream must be nonempty");
    ensure!(request.boundary_bytes <= 2 * GIB, "boundary exceeds 2 GiB");
    ensure!(
        request.lift_bytes_per_weight_byte > 0,
        "field lift expansion must be nonzero"
    );
    ensure!(
        request.max_cell_per_shard > 0,
        "shard budget must be nonzero"
    );

    let class = capability.class();
    let target = match class {
        GpuClass::Rtx5070Ti | GpuClass::Conservative => 64 * MIB,
        GpuClass::Rtx4090 => 128 * MIB,
        GpuClass::Rtx5090 => 256 * MIB,
    };
    let expansion = u64::from(request.lift_bytes_per_weight_byte);
    let reserved_vram_bytes = capability.vram_bytes / 2;
    let stream_budget = capability.vram_bytes - reserved_vram_bytes;
    let max_tile = stream_budget / (2 * expansion);
    let tile_bytes = target.min(max_tile).min(request.weight_bytes).max(MIB);
    ensure!(
        tile_bytes <= request.weight_bytes,
        "weight stream smaller than minimum tile"
    );
    let host_buffer_count = 2;
    let device_buffer_count = 2;
    let host_buffer_bytes = tile_bytes * u64::from(host_buffer_count);
    let device_buffer_bytes = tile_bytes * expansion * u64::from(device_buffer_count);
    ensure!(
        device_buffer_bytes <= stream_budget,
        "stream buffers exceed bounded VRAM allocation"
    );

    // One BabyBear cell occupies four raw bytes. Keep the selected shard's raw
    // cells inside the VRAM half reserved for proof state; the existing Ceno
    // cost model remains the final admission authority.
    let vram_cell_cap = reserved_vram_bytes / 4;
    let max_cell_per_shard = request.max_cell_per_shard.min(vram_cell_cap);
    Ok(TensorStreamingPlan {
        class,
        tile_bytes,
        host_buffer_count,
        device_buffer_count,
        host_buffer_bytes,
        device_buffer_bytes,
        reserved_vram_bytes,
        max_cell_per_shard,
        h2d_bytes: request.weight_bytes,
        d2h_bytes: request.boundary_bytes,
        full_model_resident: false,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TensorLifetime {
    Ephemeral,
    BlockBoundary,
    Persistent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReducedFusionCost {
    pub primitive_ecalls: u32,
    pub primitive_journal_words: u32,
    pub primitive_custom_records: u32,
    pub primitive_ephemeral_words: u32,
    pub fused_ecalls: u32,
    pub fused_journal_words: u32,
    pub fused_boundary_words: u32,
    pub retained_weight_commitments: u32,
    pub removed_ephemeral_words: u32,
}

/// Exact Gate-3 reduced-layer boundary inventory (width four).
///
/// The fused design has two atomic domains: attention and FFN. Their X/Y
/// boundaries remain authenticated. Seven committed MatMul weight openings
/// remain private inputs bound inside the physical chips. Only intermediate
/// activation edges are removed from the custom-record/memory boundary.
pub const fn reduced_layer_fusion_cost() -> ReducedFusionCost {
    // 7 MatMuls * 34 words + 28 scalar relations * 10 + attention * 48.
    let primitive_journal_words = 7 * 34 + 28 * 10 + 48;
    // Each split ecall/core pair exchanges an input and output custom record.
    let primitive_ecalls = 7 + 28 + 1;
    // Twelve width-four attention edges and eight width-four FFN edges are
    // local to their fused physical domain.
    let primitive_ephemeral_words = (12 + 8) * 4;
    ReducedFusionCost {
        primitive_ecalls,
        primitive_journal_words,
        primitive_custom_records: primitive_ecalls * 2,
        primitive_ephemeral_words,
        fused_ecalls: 2,
        // Two 32-word descriptors, 16 X/Y words, and seven eight-word roots.
        fused_journal_words: 2 * 32 + 4 * 4 + 7 * 8,
        // X/Y for each atomic block. The shared attention->FFN boundary is
        // intentionally retained until a measured claim-bus design exists.
        fused_boundary_words: 2 * 2 * 4,
        retained_weight_commitments: 7,
        removed_ephemeral_words: primitive_ephemeral_words,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> TensorStreamingRequest {
        TensorStreamingRequest {
            // zkLLM-compatible int32 storage for approximately seven billion
            // parameters. This intentionally exceeds every supported VRAM.
            weight_bytes: 28_000_000_000,
            boundary_bytes: 128 * 4096 * 4,
            lift_bytes_per_weight_byte: 4,
            max_cell_per_shard: 1 << 32,
        }
    }

    #[test]
    fn adaptive_profiles_are_bounded_and_never_require_model_residency() {
        for (gpu, class, tile) in [
            (GpuCapability::RTX4090, GpuClass::Rtx4090, 128 * MIB),
            (GpuCapability::RTX5070_TI, GpuClass::Rtx5070Ti, 64 * MIB),
            (GpuCapability::RTX5090, GpuClass::Rtx5090, 256 * MIB),
        ] {
            let plan = plan_streaming(gpu, request()).unwrap();
            assert_eq!(plan.class, class);
            assert_eq!(plan.tile_bytes, tile);
            assert_eq!(plan.host_buffer_count, 2);
            assert_eq!(plan.device_buffer_count, 2);
            assert!(plan.device_buffer_bytes <= gpu.vram_bytes / 2);
            assert!(plan.max_cell_per_shard * 4 <= gpu.vram_bytes / 2);
            assert_eq!(plan.h2d_bytes, request().weight_bytes);
            assert_eq!(plan.d2h_bytes, request().boundary_bytes);
            assert!(!plan.full_model_resident);
        }
    }

    #[test]
    fn unknown_gpu_falls_back_conservatively_and_invalid_requests_fail() {
        let gpu = GpuCapability {
            sm: 100,
            vram_bytes: 12 * GIB,
        };
        assert_eq!(
            plan_streaming(gpu, request()).unwrap().class,
            GpuClass::Conservative
        );
        let mut invalid = request();
        invalid.max_cell_per_shard = 0;
        assert!(plan_streaming(gpu, invalid).is_err());
    }

    #[test]
    fn fusion_inventory_removes_only_ephemeral_edges() {
        let cost = reduced_layer_fusion_cost();
        assert_eq!(cost.primitive_ecalls, 36);
        assert_eq!(cost.primitive_journal_words, 566);
        assert_eq!(cost.primitive_custom_records, 72);
        assert_eq!(cost.fused_ecalls, 2);
        assert_eq!(cost.fused_journal_words, 136);
        assert_eq!(cost.fused_boundary_words, 16);
        assert_eq!(cost.retained_weight_commitments, 7);
        assert_eq!(cost.removed_ephemeral_words, 80);
    }
}
