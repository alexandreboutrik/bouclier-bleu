{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "bouclier-bleu-dev";

  nativeBuildInputs = with pkgs; [
    # Rust Toolchain
    cargo
    rustc
    rustfmt
    clippy
    #rust-analyzer

    # C/eBPF Compilers and Tools
    clang
    llvm
    pkg-config
  ];

  buildInputs = with pkgs; [
    libbpf
    elfutils       # libelf, required by libbpf-sys
    zlib           # Required by libbpf-sys
    linuxHeaders   # Kernel headers for eBPF structs
  ];

  # This tells the Nix compiler wrapper to stop injecting 
  # hardening flags that the BPF target doesn't support.
  hardeningDisable = [ "all" ];

  # Environment Variables
  # bindgen (used by libbpf-rs) requires LIBCLANG_PATH to be set in NixOS
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
  
  # Ensure the C compiler knows where the kernel headers are
  C_INCLUDE_PATH = "${pkgs.linuxHeaders}/include";

  shellHook = ''
    echo "🛡️ Welcome to the bouclier-bleu NixOS dev shell!"
    echo "------------------------------------------------"
    echo "Rust version:  $(rustc --version)"
    echo "Clang version: $(clang --version | head -n 1)"
    echo "------------------------------------------------"
    echo "Run: cargo build"
  '';
}
