//! Zero-Dependency **Headless Linux GPU Compute Bridge (`credit-gpu-sys`)**.
//!
//! - **Zero external `crates.io` dependencies.**
//! - **Strict `unsafe` boundary:** Encapsulates dynamic runtime loading (`dlopen` / `dlsym` of
//!   `libOpenCL.so.1` across NVIDIA CUDA, AMD ROCm, and Intel headless Linux servers) inside this
//!   single platform crate, exposing a 100% safe Rust `HeadlessLinuxGpu` API to `credit-node`.
//! - **Zero X11 / Wayland / OpenGL requirement:** Talks directly to headless Linux compute ICDs.
//! - **Zero link-time GPU requirement:** CPU-only Linux droplets without `libOpenCL.so.1` return
//!   `HeadlessLinuxGpu::probe() == None` in `< 0.1 ms` and run pure CPU `PoNC` cleanly.

/// OpenCL C99 8-round RFC 6234 SHA-256 `RecursiveZkState` folding kernel (bit-identical to
/// `credit_ponc::execute_zk_fold_from_context` and the `wgpu` WGSL desktop shader).
pub const OPENCL_ZK_FOLD_KERNEL_SRC: &str = r#"
__constant uint K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

inline uint rotr32(uint x, uint n) {
    return (x >> n) | (x << (32u - n));
}

inline void sha256_block(uint w[16], uint h_out[8]) {
    uint schedule[64];
    for (int i = 0; i < 16; ++i) {
        schedule[i] = w[i];
    }
    for (int i = 16; i < 64; ++i) {
        uint s0 = rotr32(schedule[i - 15], 7u) ^ rotr32(schedule[i - 15], 18u) ^ (schedule[i - 15] >> 3u);
        uint s1 = rotr32(schedule[i - 2], 17u) ^ rotr32(schedule[i - 2], 19u) ^ (schedule[i - 2] >> 10u);
        schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
    }

    uint a = 0x6a09e667u;
    uint b = 0xbb67ae85u;
    uint c = 0x3c6ef372u;
    uint d = 0xa54ff53au;
    uint e = 0x510e527fu;
    uint f = 0x9b05688cu;
    uint g = 0x1f83d9abu;
    uint h = 0x5be0cd19u;

    for (int i = 0; i < 64; ++i) {
        uint S1 = rotr32(e, 6u) ^ rotr32(e, 11u) ^ rotr32(e, 25u);
        uint ch = (e & f) ^ ((~e) & g);
        uint temp1 = h + S1 + ch + K256[i] + schedule[i];
        uint S0 = rotr32(a, 2u) ^ rotr32(a, 13u) ^ rotr32(a, 22u);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    h_out[0] = 0x6a09e667u + a;
    h_out[1] = 0xbb67ae85u + b;
    h_out[2] = 0x3c6ef372u + c;
    h_out[3] = 0xa54ff53au + d;
    h_out[4] = 0x510e527fu + e;
    h_out[5] = 0x9b05688cu + f;
    h_out[6] = 0x1f83d9abu + g;
    h_out[7] = 0x5be0cd19u + h;
}

__kernel void zk_fold_search(__global const uint* params, __global volatile uint* out_best) {
    uint gid = (uint)get_global_id(0);
    ulong base_nonce = ((ulong)params[9] << 32) | (ulong)params[8];
    uint min_zeros = params[10];
    ulong nonce = base_nonce + (ulong)gid;

    uint w[16];
    for (int i = 0; i < 8; ++i) {
        w[i] = params[i];
    }
    w[8] = (uint)(nonce >> 32);
    w[9] = (uint)(nonce & 0xffffffffUL);
    w[10] = 0x80000000u;
    w[11] = 0u;
    w[12] = 0u;
    w[13] = 0u;
    w[14] = 0u;
    w[15] = 320u;

    uint st[8];
    sha256_block(w, st);

    for (uint r = 1u; r < 8u; ++r) {
        for (int i = 0; i < 8; ++i) {
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
        sha256_block(w, st);
    }

    uint z = (st[0] != 0u) ? clz(st[0]) : (32u + clz(st[1]));
    if (z >= min_zeros) {
        uint score = (z << 24) | ((~st[0] >> 8) & 0x00ffffffu);
        uint prev = atomic_max(&out_best[0], score);
        if (score > prev && out_best[0] == score) {
            out_best[1] = (uint)(nonce & 0xffffffffUL);
            out_best[2] = (uint)(nonce >> 32);
            out_best[3] = z;
        }
    }
}
"#;

#[cfg(target_os = "linux")]
mod imp {
    use super::OPENCL_ZK_FOLD_KERNEL_SRC;
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::Mutex;

    const RTLD_NOW: i32 = 2;
    const CL_SUCCESS: i32 = 0;
    const CL_DEVICE_TYPE_GPU: u64 = 1 << 2;
    const CL_DEVICE_NAME: u32 = 0x102B;
    const CL_MEM_READ_ONLY: u64 = 1 << 2;
    const CL_MEM_READ_WRITE: u64 = 1 << 0;

    #[link(name = "dl")]
    unsafe extern "C" {
        fn dlopen(filename: *const u8, flags: i32) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const u8) -> *mut c_void;
        fn dlclose(handle: *mut c_void) -> i32;
    }

    type FnGetPlatformIDs = unsafe extern "C" fn(u32, *mut *mut c_void, *mut u32) -> i32;
    type FnGetDeviceIDs =
        unsafe extern "C" fn(*mut c_void, u64, u32, *mut *mut c_void, *mut u32) -> i32;
    type FnGetDeviceInfo =
        unsafe extern "C" fn(*mut c_void, u32, usize, *mut c_void, *mut usize) -> i32;
    type FnCreateContext = unsafe extern "C" fn(
        *const isize,
        u32,
        *const *mut c_void,
        *const c_void,
        *mut c_void,
        *mut i32,
    ) -> *mut c_void;
    type FnCreateCommandQueue =
        unsafe extern "C" fn(*mut c_void, *mut c_void, u64, *mut i32) -> *mut c_void;
    type FnCreateProgramWithSource = unsafe extern "C" fn(
        *mut c_void,
        u32,
        *const *const u8,
        *const usize,
        *mut i32,
    ) -> *mut c_void;
    type FnBuildProgram = unsafe extern "C" fn(
        *mut c_void,
        u32,
        *const *mut c_void,
        *const u8,
        *const c_void,
        *mut c_void,
    ) -> i32;
    type FnCreateKernel = unsafe extern "C" fn(*mut c_void, *const u8, *mut i32) -> *mut c_void;
    type FnCreateBuffer =
        unsafe extern "C" fn(*mut c_void, u64, usize, *mut c_void, *mut i32) -> *mut c_void;
    type FnEnqueueWriteBuffer = unsafe extern "C" fn(
        *mut c_void,
        *mut c_void,
        u32,
        usize,
        usize,
        *const c_void,
        u32,
        *const *mut c_void,
        *mut *mut c_void,
    ) -> i32;
    type FnEnqueueReadBuffer = unsafe extern "C" fn(
        *mut c_void,
        *mut c_void,
        u32,
        usize,
        usize,
        *mut c_void,
        u32,
        *const *mut c_void,
        *mut *mut c_void,
    ) -> i32;
    type FnSetKernelArg = unsafe extern "C" fn(*mut c_void, u32, usize, *const c_void) -> i32;
    type FnEnqueueNDRangeKernel = unsafe extern "C" fn(
        *mut c_void,
        *mut c_void,
        u32,
        *const usize,
        *const usize,
        *const usize,
        u32,
        *const *mut c_void,
        *mut *mut c_void,
    ) -> i32;
    type FnFinish = unsafe extern "C" fn(*mut c_void) -> i32;
    type FnReleaseHandle = unsafe extern "C" fn(*mut c_void) -> i32;

    struct OpenClSession {
        lib: *mut c_void,
        ctx: *mut c_void,
        queue: *mut c_void,
        program: *mut c_void,
        kernel: *mut c_void,
        params_buf: *mut c_void,
        out_buf: *mut c_void,
        enqueue_write: FnEnqueueWriteBuffer,
        enqueue_read: FnEnqueueReadBuffer,
        set_arg: FnSetKernelArg,
        enqueue_nd: FnEnqueueNDRangeKernel,
        finish: FnFinish,
        rel_mem: FnReleaseHandle,
        rel_kernel: FnReleaseHandle,
        rel_prog: FnReleaseHandle,
        rel_queue: FnReleaseHandle,
        rel_ctx: FnReleaseHandle,
    }

    unsafe impl Send for OpenClSession {}

    impl Drop for OpenClSession {
        fn drop(&mut self) {
            unsafe {
                let _ = (self.rel_mem)(self.params_buf);
                let _ = (self.rel_mem)(self.out_buf);
                let _ = (self.rel_kernel)(self.kernel);
                let _ = (self.rel_prog)(self.program);
                let _ = (self.rel_queue)(self.queue);
                let _ = (self.rel_ctx)(self.ctx);
                let _ = dlclose(self.lib);
            }
        }
    }

    unsafe fn load_sym<T>(lib: *mut c_void, nul_terminated: &[u8]) -> Option<T> {
        let raw = unsafe { dlsym(lib, nul_terminated.as_ptr()) };
        if raw.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&raw) })
        }
    }

    pub struct HeadlessLinuxGpu {
        device_name: String,
        inner: Mutex<OpenClSession>,
    }

    impl HeadlessLinuxGpu {
        pub fn probe() -> Option<Self> {
            let candidates: &[&[u8]] = &[
                b"libOpenCL.so.1\0",
                b"/usr/lib/x86_64-linux-gnu/libOpenCL.so.1\0",
                b"/usr/lib64/libOpenCL.so.1\0",
                b"/usr/local/cuda/lib64/libOpenCL.so.1\0",
            ];
            let mut lib = ptr::null_mut();
            for c in candidates {
                lib = unsafe { dlopen(c.as_ptr(), RTLD_NOW) };
                if !lib.is_null() {
                    break;
                }
            }
            if lib.is_null() {
                return None;
            }

            unsafe {
                let Some(get_platforms) = load_sym::<FnGetPlatformIDs>(lib, b"clGetPlatformIDs\0")
                else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(get_devices) = load_sym::<FnGetDeviceIDs>(lib, b"clGetDeviceIDs\0") else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(get_info) = load_sym::<FnGetDeviceInfo>(lib, b"clGetDeviceInfo\0") else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(create_ctx) = load_sym::<FnCreateContext>(lib, b"clCreateContext\0")
                else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(create_queue) =
                    load_sym::<FnCreateCommandQueue>(lib, b"clCreateCommandQueue\0")
                else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(create_prog) =
                    load_sym::<FnCreateProgramWithSource>(lib, b"clCreateProgramWithSource\0")
                else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(build_prog) = load_sym::<FnBuildProgram>(lib, b"clBuildProgram\0") else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(create_kernel) = load_sym::<FnCreateKernel>(lib, b"clCreateKernel\0")
                else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(create_buf) = load_sym::<FnCreateBuffer>(lib, b"clCreateBuffer\0") else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(enqueue_write) =
                    load_sym::<FnEnqueueWriteBuffer>(lib, b"clEnqueueWriteBuffer\0")
                else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(enqueue_read) =
                    load_sym::<FnEnqueueReadBuffer>(lib, b"clEnqueueReadBuffer\0")
                else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(set_arg) = load_sym::<FnSetKernelArg>(lib, b"clSetKernelArg\0") else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(enqueue_nd) =
                    load_sym::<FnEnqueueNDRangeKernel>(lib, b"clEnqueueNDRangeKernel\0")
                else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(finish) = load_sym::<FnFinish>(lib, b"clFinish\0") else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(rel_mem) = load_sym::<FnReleaseHandle>(lib, b"clReleaseMemObject\0")
                else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(rel_kernel) = load_sym::<FnReleaseHandle>(lib, b"clReleaseKernel\0")
                else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(rel_prog) = load_sym::<FnReleaseHandle>(lib, b"clReleaseProgram\0") else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(rel_queue) = load_sym::<FnReleaseHandle>(lib, b"clReleaseCommandQueue\0")
                else {
                    let _ = dlclose(lib);
                    return None;
                };
                let Some(rel_ctx) = load_sym::<FnReleaseHandle>(lib, b"clReleaseContext\0") else {
                    let _ = dlclose(lib);
                    return None;
                };

                let mut platforms = [ptr::null_mut(); 8];
                let mut num_platforms = 0u32;
                if get_platforms(8, platforms.as_mut_ptr(), &mut num_platforms) != CL_SUCCESS
                    || num_platforms == 0
                {
                    let _ = dlclose(lib);
                    return None;
                }

                let mut chosen_dev = ptr::null_mut();
                for &plat in &platforms[..(num_platforms as usize).min(8)] {
                    let mut dev = ptr::null_mut();
                    let mut n_dev = 0u32;
                    if get_devices(plat, CL_DEVICE_TYPE_GPU, 1, &mut dev, &mut n_dev) == CL_SUCCESS
                        && n_dev > 0
                        && !dev.is_null()
                    {
                        chosen_dev = dev;
                        break;
                    }
                }
                if chosen_dev.is_null() {
                    let _ = dlclose(lib);
                    return None;
                }

                let mut name_buf = [0u8; 128];
                let mut actual_len = 0usize;
                let _ = get_info(
                    chosen_dev,
                    CL_DEVICE_NAME,
                    name_buf.len() - 1,
                    name_buf.as_mut_ptr().cast(),
                    &mut actual_len,
                );
                let end = name_buf
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(actual_len.min(127));
                let device_name = String::from_utf8_lossy(&name_buf[..end]).trim().to_owned();

                let mut err = 0i32;
                let ctx = create_ctx(
                    ptr::null(),
                    1,
                    &chosen_dev,
                    ptr::null(),
                    ptr::null_mut(),
                    &mut err,
                );
                if ctx.is_null() || err != CL_SUCCESS {
                    let _ = dlclose(lib);
                    return None;
                }

                let queue = create_queue(ctx, chosen_dev, 0, &mut err);
                if queue.is_null() || err != CL_SUCCESS {
                    let _ = rel_ctx(ctx);
                    let _ = dlclose(lib);
                    return None;
                }

                let src_ptr = OPENCL_ZK_FOLD_KERNEL_SRC.as_ptr();
                let src_len = OPENCL_ZK_FOLD_KERNEL_SRC.len();
                let program = create_prog(ctx, 1, &src_ptr, &src_len, &mut err);
                if program.is_null() || err != CL_SUCCESS {
                    let _ = rel_queue(queue);
                    let _ = rel_ctx(ctx);
                    let _ = dlclose(lib);
                    return None;
                }
                if build_prog(
                    program,
                    1,
                    &chosen_dev,
                    b"\0".as_ptr(),
                    ptr::null(),
                    ptr::null_mut(),
                ) != CL_SUCCESS
                {
                    let _ = rel_prog(program);
                    let _ = rel_queue(queue);
                    let _ = rel_ctx(ctx);
                    let _ = dlclose(lib);
                    return None;
                }

                let kernel = create_kernel(program, b"zk_fold_search\0".as_ptr(), &mut err);
                if kernel.is_null() || err != CL_SUCCESS {
                    let _ = rel_prog(program);
                    let _ = rel_queue(queue);
                    let _ = rel_ctx(ctx);
                    let _ = dlclose(lib);
                    return None;
                }

                let params_buf =
                    create_buf(ctx, CL_MEM_READ_ONLY, 12 * 4, ptr::null_mut(), &mut err);
                let out_buf = create_buf(ctx, CL_MEM_READ_WRITE, 4 * 4, ptr::null_mut(), &mut err);
                if params_buf.is_null() || out_buf.is_null() || err != CL_SUCCESS {
                    if !params_buf.is_null() {
                        let _ = rel_mem(params_buf);
                    }
                    if !out_buf.is_null() {
                        let _ = rel_mem(out_buf);
                    }
                    let _ = rel_kernel(kernel);
                    let _ = rel_prog(program);
                    let _ = rel_queue(queue);
                    let _ = rel_ctx(ctx);
                    let _ = dlclose(lib);
                    return None;
                }

                Some(Self {
                    device_name: format!("{device_name} (Linux Headless OpenCL)"),
                    inner: Mutex::new(OpenClSession {
                        lib,
                        ctx,
                        queue,
                        program,
                        kernel,
                        params_buf,
                        out_buf,
                        enqueue_write,
                        enqueue_read,
                        set_arg,
                        enqueue_nd,
                        finish,
                        rel_mem,
                        rel_kernel,
                        rel_prog,
                        rel_queue,
                        rel_ctx,
                    }),
                })
            }
        }

        pub fn device_name(&self) -> &str {
            &self.device_name
        }

        pub fn search_zk_fold_batch(
            &self,
            context_hash: &[u8; 32],
            base_nonce: u64,
            batch_threads: u32,
            min_zero_bits: u32,
        ) -> Option<(u64, u32)> {
            let mut params = [0u32; 12];
            for (i, slot) in params.iter_mut().take(8).enumerate() {
                *slot = u32::from_be_bytes(context_hash[i * 4..i * 4 + 4].try_into().ok()?);
            }
            params[8] = (base_nonce & 0xffff_ffff) as u32;
            params[9] = (base_nonce >> 32) as u32;
            params[10] = min_zero_bits;
            let zero_out = [0u32; 4];
            let mut read_out = [0u32; 4];
            let global_work_size: usize = (batch_threads.max(256) as usize + 255) & !255;
            let local_work_size: usize = 256;

            let guard = self.inner.lock().ok()?;
            unsafe {
                if (guard.enqueue_write)(
                    guard.queue,
                    guard.params_buf,
                    1,
                    0,
                    48,
                    params.as_ptr().cast(),
                    0,
                    ptr::null(),
                    ptr::null_mut(),
                ) != CL_SUCCESS
                {
                    return None;
                }
                if (guard.enqueue_write)(
                    guard.queue,
                    guard.out_buf,
                    1,
                    0,
                    16,
                    zero_out.as_ptr().cast(),
                    0,
                    ptr::null(),
                    ptr::null_mut(),
                ) != CL_SUCCESS
                {
                    return None;
                }
                if (guard.set_arg)(
                    guard.kernel,
                    0,
                    std::mem::size_of::<*mut c_void>(),
                    (&guard.params_buf as *const *mut c_void).cast(),
                ) != CL_SUCCESS
                {
                    return None;
                }
                if (guard.set_arg)(
                    guard.kernel,
                    1,
                    std::mem::size_of::<*mut c_void>(),
                    (&guard.out_buf as *const *mut c_void).cast(),
                ) != CL_SUCCESS
                {
                    return None;
                }
                if (guard.enqueue_nd)(
                    guard.queue,
                    guard.kernel,
                    1,
                    ptr::null(),
                    &global_work_size,
                    &local_work_size,
                    0,
                    ptr::null(),
                    ptr::null_mut(),
                ) != CL_SUCCESS
                {
                    return None;
                }
                let _ = (guard.finish)(guard.queue);
                if (guard.enqueue_read)(
                    guard.queue,
                    guard.out_buf,
                    1,
                    0,
                    16,
                    read_out.as_mut_ptr().cast(),
                    0,
                    ptr::null(),
                    ptr::null_mut(),
                ) != CL_SUCCESS
                {
                    return None;
                }
            }
            if read_out[0] == 0 {
                return None;
            }
            let winning_nonce = ((read_out[2] as u64) << 32) | (read_out[1] as u64);
            Some((winning_nonce, read_out[3]))
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    pub struct HeadlessLinuxGpu {
        _private: (),
    }

    impl HeadlessLinuxGpu {
        /// Non-Linux builds use `wgpu` inside `credit-desktop`; headless `dlopen` targets Linux servers.
        pub fn probe() -> Option<Self> {
            None
        }

        pub fn device_name(&self) -> &str {
            ""
        }

        pub fn search_zk_fold_batch(
            &self,
            _context_hash: &[u8; 32],
            _base_nonce: u64,
            _batch_threads: u32,
            _min_zero_bits: u32,
        ) -> Option<(u64, u32)> {
            None
        }
    }
}

pub use imp::HeadlessLinuxGpu;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opencl_kernel_source_contains_canonical_sha256_and_entry_point() {
        assert!(OPENCL_ZK_FOLD_KERNEL_SRC.contains("__kernel void zk_fold_search"));
        assert!(OPENCL_ZK_FOLD_KERNEL_SRC.contains("0x428a2f98u"));
        // Verify graceful runtime probe never panics even on CPU-only machines:
        let _ = HeadlessLinuxGpu::probe();
    }
}
