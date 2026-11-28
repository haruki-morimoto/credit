//! Cross-platform `wgpu` (`DirectX 12` / `Metal` / `Vulkan`) WGSL Compute Accelerator for
//! consumer desktops (`100%` `#![forbid(unsafe_code)]`).
//!
//! Executes the exact same 8-round RFC 6234 SHA-256 `RecursiveZkState` state-folding kernel as
//! `credit_ponc::execute_zk_fold_from_context` and `credit_gpu_sys::HeadlessLinuxGpu`, sleeping
//! at `0W` when no epoch transactions are in flight and accelerating ZK proving across any
//! NVIDIA, AMD, Intel, or Apple Silicon GPU when payments flow.

use std::sync::Mutex;
use std::sync::mpsc;

use credit_node::GpuZkBatchProver;

/// Portable WGSL compute shader (256 threads/workgroup) bit-identical to `execute_zk_fold_from_context`.
pub const WGSL_ZK_FOLD_SHADER: &str = r#"
struct Params {
    ctx0: u32,
    ctx1: u32,
    ctx2: u32,
    ctx3: u32,
    ctx4: u32,
    ctx5: u32,
    ctx6: u32,
    ctx7: u32,
    base_lo: u32,
    base_hi: u32,
    min_zeros: u32,
    pad0: u32,
}

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read_write> out_best: array<atomic<u32>, 4>;

fn rotr32(x: u32, n: u32) -> u32 {
    return (x >> n) | (x << (32u - n));
}

fn k256(i: u32) -> u32 {
    var k = array<u32, 64>(
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    );
    return k[i];
}

fn sha256_block(w_in: array<u32, 16>) -> array<u32, 8> {
    var schedule: array<u32, 64>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        schedule[i] = w_in[i];
    }
    for (var i = 16u; i < 64u; i = i + 1u) {
        let s0 = rotr32(schedule[i - 15u], 7u) ^ rotr32(schedule[i - 15u], 18u) ^ (schedule[i - 15u] >> 3u);
        let s1 = rotr32(schedule[i - 2u], 17u) ^ rotr32(schedule[i - 2u], 19u) ^ (schedule[i - 2u] >> 10u);
        schedule[i] = schedule[i - 16u] + s0 + schedule[i - 7u] + s1;
    }

    var a = 0x6a09e667u;
    var b = 0xbb67ae85u;
    var c = 0x3c6ef372u;
    var d = 0xa54ff53au;
    var e = 0x510e527fu;
    var f = 0x9b05688cu;
    var g = 0x1f83d9abu;
    var h = 0x5be0cd19u;

    for (var i = 0u; i < 64u; i = i + 1u) {
        let S1 = rotr32(e, 6u) ^ rotr32(e, 11u) ^ rotr32(e, 25u);
        let ch = (e & f) ^ ((~e) & g);
        let temp1 = h + S1 + ch + k256(i) + schedule[i];
        let S0 = rotr32(a, 2u) ^ rotr32(a, 13u) ^ rotr32(a, 22u);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    return array<u32, 8>(
        0x6a09e667u + a,
        0xbb67ae85u + b,
        0x3c6ef372u + c,
        0xa54ff53au + d,
        0x510e527fu + e,
        0x9b05688cu + f,
        0x1f83d9abu + g,
        0x5be0cd19u + h
    );
}

@compute @workgroup_size(256)
fn zk_fold_search(@builtin(global_invocation_id) gid: vec3<u32>) {
    let tid = gid.x;
    let nonce_lo = params.base_lo + tid;
    let carry = select(0u, 1u, nonce_lo < params.base_lo);
    let nonce_hi = params.base_hi + carry;

    var w: array<u32, 16>;
    w[0] = params.ctx0;
    w[1] = params.ctx1;
    w[2] = params.ctx2;
    w[3] = params.ctx3;
    w[4] = params.ctx4;
    w[5] = params.ctx5;
    w[6] = params.ctx6;
    w[7] = params.ctx7;
    w[8] = nonce_hi;
    w[9] = nonce_lo;
    w[10] = 0x80000000u;
    w[11] = 0u;
    w[12] = 0u;
    w[13] = 0u;
    w[14] = 0u;
    w[15] = 320u;

    var st = sha256_block(w);

    for (var r = 1u; r < 8u; r = r + 1u) {
        for (var i = 0u; i < 8u; i = i + 1u) {
            w[i] = st[i];
        }
        w[8] = r;
        w[9] = 0x80000000u;
        w[10] = 0u;
        w[11] = 0u;
        w[12] = 0u;
        w[13] = 0u;
        w[14] = 0u;
        w[15] = 288u;
        st = sha256_block(w);
    }

    let z = select(32u + countLeadingZeros(st[1]), countLeadingZeros(st[0]), st[0] != 0u);
    if (z >= params.min_zeros) {
        let score = (z << 24u) | ((~st[0] >> 8u) & 0x00ffffffu);
        let prev = atomicMax(&out_best[0], score);
        if (score > prev) {
            atomicStore(&out_best[1], nonce_lo);
            atomicStore(&out_best[2], nonce_hi);
            atomicStore(&out_best[3], z);
        }
    }
}
"#;

struct WgpuInner {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    bind_group: wgpu::BindGroup,
    params_buf: wgpu::Buffer,
    out_buf: wgpu::Buffer,
    staging_buf: wgpu::Buffer,
}

pub struct WgpuZkProver {
    device_label: String,
    inner: Mutex<WgpuInner>,
}

impl WgpuZkProver {
    pub fn device_name(&self) -> &str {
        &self.device_label
    }

    /// Probes any hardware (or fallback) `wgpu` adapter (`DX12` / `Metal` / `Vulkan`) without panicking.
    pub fn probe() -> Option<Self> {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: wgpu::Backends::PRIMARY,
            ..Default::default()
        });
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            compatible_surface: None,
            force_fallback_adapter: false,
        }))
        .or_else(|| {
            pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::LowPower,
                compatible_surface: None,
                force_fallback_adapter: true,
            }))
        })?;

        let info = adapter.get_info();
        let device_label = format!("{} ({:?})", info.name.trim(), info.backend);

        let (device, queue) = pollster::block_on(adapter.request_device(
            &wgpu::DeviceDescriptor {
                label: Some("credits-zk-wgpu-device"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::downlevel_defaults(),
                memory_hints: wgpu::MemoryHints::Performance,
            },
            None,
        ))
        .ok()?;

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("credits-zk-fold-wgsl"),
            source: wgpu::ShaderSource::Wgsl(WGSL_ZK_FOLD_SHADER.into()),
        });

        let params_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("zk-params"),
            size: 48,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let out_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("zk-out"),
            size: 16,
            usage: wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_DST
                | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let staging_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("zk-staging"),
            size: 16,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let bind_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("zk-bind-layout"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });

        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("zk-pipe-layout"),
            bind_group_layouts: &[&bind_layout],
            push_constant_ranges: &[],
        });

        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("zk-fold-pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: Some("zk_fold_search"),
            compilation_options: wgpu::PipelineCompilationOptions::default(),
            cache: None,
        });

        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("zk-bind-group"),
            layout: &bind_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: params_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: out_buf.as_entire_binding(),
                },
            ],
        });

        Some(Self {
            device_label,
            inner: Mutex::new(WgpuInner {
                device,
                queue,
                pipeline,
                bind_group,
                params_buf,
                out_buf,
                staging_buf,
            }),
        })
    }
}

impl GpuZkBatchProver for WgpuZkProver {
    fn device_name(&self) -> &str {
        &self.device_label
    }

    fn search_zk_fold_batch(
        &self,
        context_hash: &[u8; 32],
        base_nonce: u64,
        batch_threads: u32,
        min_zero_bits: u32,
    ) -> Option<(u64, u32)> {
        let mut param_bytes = [0u8; 48];
        for i in 0..8usize {
            let word_be = u32::from_be_bytes(context_hash[i * 4..i * 4 + 4].try_into().ok()?);
            param_bytes[i * 4..i * 4 + 4].copy_from_slice(&word_be.to_le_bytes());
        }
        param_bytes[32..36].copy_from_slice(&((base_nonce & 0xffff_ffff) as u32).to_le_bytes());
        param_bytes[36..40].copy_from_slice(&((base_nonce >> 32) as u32).to_le_bytes());
        param_bytes[40..44].copy_from_slice(&min_zero_bits.to_le_bytes());

        let workgroups = batch_threads.max(256).div_ceil(256);
        let guard = self.inner.lock().ok()?;
        guard.queue.write_buffer(&guard.params_buf, 0, &param_bytes);
        guard.queue.write_buffer(&guard.out_buf, 0, &[0u8; 16]);

        let mut encoder = guard
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("zk-fold-enc"),
            });
        {
            let mut cpass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("zk-fold-pass"),
                timestamp_writes: None,
            });
            cpass.set_pipeline(&guard.pipeline);
            cpass.set_bind_group(0, &guard.bind_group, &[]);
            cpass.dispatch_workgroups(workgroups, 1, 1);
        }
        encoder.copy_buffer_to_buffer(&guard.out_buf, 0, &guard.staging_buf, 0, 16);
        guard.queue.submit(Some(encoder.finish()));

        let slice = guard.staging_buf.slice(..);
        let (tx, rx) = mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |res| {
            let _ = tx.send(res);
        });
        guard.device.poll(wgpu::Maintain::Wait);
        rx.recv().ok()?.ok()?;

        let mapped = slice.get_mapped_range();
        let score = u32::from_le_bytes(mapped[0..4].try_into().ok()?);
        let n_lo = u32::from_le_bytes(mapped[4..8].try_into().ok()?);
        let n_hi = u32::from_le_bytes(mapped[8..12].try_into().ok()?);
        let zeros = u32::from_le_bytes(mapped[12..16].try_into().ok()?);
        drop(mapped);
        guard.staging_buf.unmap();

        if score == 0 {
            return None;
        }
        let winning_nonce = ((n_hi as u64) << 32) | (n_lo as u64);
        Some((winning_nonce, zeros))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credit_ponc::{MIN_ZK_ZERO_BITS, execute_zk_fold_from_context};
    use credit_types::Hash32;

    #[test]
    fn wgpu_shader_matches_pure_rust_zk_fold_bit_for_bit() {
        let Some(prover) = WgpuZkProver::probe() else {
            return; // Graceful skip on headless CI boxes with zero DX12/Vulkan/GL software rasterizer
        };
        let ctx = Hash32::from_bytes([0x5a; 32]);
        let (winning_nonce, reported_zeros) = prover
            .search_zk_fold_batch(ctx.as_bytes(), 42_000, 4_096, MIN_ZK_ZERO_BITS)
            .expect("4,096 GPU threads find >= 6 leading zero bits with P > 99.999999%");

        let cpu_digest = execute_zk_fold_from_context(&ctx, winning_nonce);
        assert!(cpu_digest.leading_zeros() >= MIN_ZK_ZERO_BITS);
        assert_eq!(cpu_digest.leading_zeros(), reported_zeros);
    }
}
