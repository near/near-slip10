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

    compile_c(&src, &manifest_dir, &out_dir);
    #[cfg(feature = "buildtime_bindgen")]
    generate_bindings(&src, &out_dir);
    #[cfg(not(feature = "buildtime_bindgen"))]
    copy_bindings(&manifest_dir, &out_dir);
}

fn compile_c(src: &Path, manifest_dir: &Path, out_dir: &Path) {
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
        // wasm32-unknown-unknown has no libc, so `<string.h>` doesn't exist and `compiler_builtings`
        // supplies the symbols, so we need to include a shim header exposing `memcpy` and `memset`.
        build.include(manifest_dir.join("wasm-shim"));
    }

    // TODO: find arch and pass arch-specific optimization flags.

    if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "wasm32" {
        let objects = build.compile_intermediates();
        write_gnu_archive(&out_dir.join("libmldsa_native.a"), &objects);
        println!("cargo:rustc-link-search=native={}", out_dir.display());
        println!("cargo:rustc-link-lib=static=mldsa_native");
    } else {
        // Emits rustc-link-lib=static=mldsa_native and rustc-link-search=OUT_DIR.
        build.compile("mldsa_native");
    }
}

fn write_gnu_archive(dst: &Path, objects: &[PathBuf]) {
    use ar_archive_writer::{
        ArchiveKind, DEFAULT_OBJECT_READER, NewArchiveMember, write_archive_to_stream,
    };
    let buffers: Vec<Vec<u8>> = objects.iter().map(|o| std::fs::read(o).unwrap()).collect();
    let members: Vec<NewArchiveMember> = buffers
        .iter()
        .zip(objects)
        .map(|(buf, path)| {
            NewArchiveMember::new(
                buf.as_slice(),
                &DEFAULT_OBJECT_READER,
                path.file_name().unwrap().to_string_lossy().into_owned(),
            )
        })
        .collect();
    let mut file = std::fs::File::create(dst).unwrap();
    write_archive_to_stream(&mut file, &members, ArchiveKind::Gnu, false, false).unwrap();
}

#[cfg(feature = "buildtime_bindgen")]
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
        // clang doesn't doesn't expose linked `mldsa65_keypair_internal`,
        // so we need to pass an visibility clang arg to set this visibility back to default.
        builder = builder.clang_arg("-fvisibility=default");
    }

    builder
        .generate()
        .expect("bindgen failed on mldsa_native.h")
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("couldn't write bindings.rs");
}

#[cfg(not(feature = "buildtime_bindgen"))]
fn copy_bindings(manifest_dir: &Path, out_dir: &Path) {
    let commited_binding = manifest_dir.join("bindings/mldsa65.rs");
    println!("cargo:rerun-if-changed={}", commited_binding.display());
    std::fs::copy(&commited_binding, out_dir.join("bindings.rs")).expect("copy commited bindings");
}
