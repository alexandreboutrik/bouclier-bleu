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
	bpftools
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
    # Dynamically generate clangd flags
    echo "--target=bpf" > compile_flags.txt
    echo "-D__TARGET_ARCH_x86" >> compile_flags.txt
    echo "-I./bpf" >> compile_flags.txt
    echo "-I./bpf/include" >> compile_flags.txt
    echo "-I./bpf/headers" >> compile_flags.txt
    echo "-I${pkgs.libbpf}/include" >> compile_flags.txt
    echo "-I${pkgs.linuxHeaders}/include" >> compile_flags.txt

	mkdir -p bpf/include
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/include/vmlinux.h

    echo "🛡️ Welcome to the bouclier-bleu NixOS dev shell!"
    echo "------------------------------------------------"
    echo "Rust version:  $(rustc --version)"
    echo "Clang version: $(clang --version | head -n 1)"
    echo "------------------------------------------------"
    echo "Run: cargo build"
  '';
}
