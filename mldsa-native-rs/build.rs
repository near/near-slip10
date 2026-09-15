use std::env;
use std::path::{Path, PathBuf};

const ML_DSA_NATIVE_DIR: &str = "mldsa-native/mldsa";
const MLD_DEFINES: &[(&str, Option<&str>)] = &[
    // In NEAR we support only ML-DSA-65
    ("MLD_CONFIG_PARAMETER_SET", Some("65")),
    // Just to make symbols become mldsa65_<name>
    ("MLD_CONFIG_NAMESPACE_PREFIX", Some("mldsa65")),
    // Core API includes `keypair_internal`, `signature_internal`, and `verify_internal`. We
    // only need `keypair_internal` and `verify_internal` for tests maybe.
    ("MLD_CONFIG_CORE_API_ONLY", None),
];

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let src = manifest_dir.join(ML_DSA_NATIVE_DIR);

    let entry = src.join("mldsa_native.c");
    if !entry.exists() {
        panic!(
            "mldsa-native sources not found at {}.\nThe C library is a git submodule; run:\n\tgit submodule update --init",
            src.display()
        );
    }

    // cc does not track sources. A directory is scanned recursively.
    println!("cargo:rerun-if-changed={}", src.display());

    compile_c(&src, &manifest_dir);
    generate_bindings(&src, &out_dir);
}

fn compile_c(src: &Path, manifest_dir: &Path) {
    let mut build = cc::Build::new();

    build
        .include(src)
        .file(src.join("mldsa_native.c"))
        // c90 is used with `stdint.h` to build the mldsa-native
        .std("c90")
        .warnings(true);

    for (name, value) in MLD_DEFINES {
        build.define(name, *value);
    }

    if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "wasm32"
        && env::var("CARGO_CFG_TARGET_OS").unwrap() == "unknown"
    {
        // For some reason wasm builds don't see memcpy and memset functions, so we need to include a
        // shim header exposing those functions.
        build.include(manifest_dir.join("wasm-shim"));
    }

    // TODO: find arch and pass arch-specific optimization flags.
    println!("cargo:rerun-if-env-changed=MLDSA_NATIVE_PORTABLE");
    let native = env::var_os("MLDSA_NATIVE_PORTABLE").is_some();
    if native {
        build
            .define("MLD_CONFIG_USE_NATIVE_BACKEND_ARITH", None)
            .define("MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202", None)
            // The native asm file includes `src/common.h`, so it needs the same `-I`/`-D` flags;
            // cc applies them to every file in the build.
            .file(src.join("mldsa_native_asm.S"));
    }
    println!(
        "cargo:warning=mldsa-native backend: {}",
        if native { "native" } else { "portable C" }
    );

    // Emits rustc-link-lib=static=mldsa_native and rustc-link-search=OUT_DIR.
    build.compile("mldsa_native");
}

fn generate_bindings(src: &Path, out_dir: &Path) {
    // The bindgen::Builder is the main entry point
    // to bindgen
    let mut builder = bindgen::Builder::default()
        .header(src.join("mldsa_native.h").to_string_lossy())
        .clang_arg(format!("-I{}", src.display()))
        // use ::core::ffi::c_int, so the crate can be no_std
        .use_core()
        // C docs contain some pseudo-code, so rustdoc might fail
        .generate_comments(false)
        // Allow only mldsa65-related stuff
        .allowlist_function("mldsa65_.*")
        .allowlist_var("MLDSA65_.*")
        .allowlist_var("MLD_ERR_.*")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    for (name, value) in MLD_DEFINES {
        builder = builder.clang_arg(match value {
            Some(v) => format!("-D{name}={v}"),
            None => format!("-D{name}"),
        })
    }

    if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "wasm32"
        && env::var("CARGO_CFG_TARGET_OS").unwrap() == "unknown"
    {
        // For some reason, the rust bindgen in wasm builds doesn't expose linked `mldsa65_keypair_internal`,
        // so we need to pass an visibility clang arg to set this visibility back to default.
        builder = builder.clang_arg("-fvisibility=default");
    }

    builder
        .generate()
        .expect("bindgen failed on mldsa_native.h")
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("couldn't write bindings.rs");
}
