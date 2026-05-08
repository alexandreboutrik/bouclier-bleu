{ useCustomGnuPG ? false }:

let
  rust_overlay = import (builtins.fetchTarball "https://github.com/oxalica/rust-overlay/archive/master.tar.gz");

  gnupg_overlay = final: prev: {
	libgpg-error = prev.libgpg-error.overrideAttrs (old: rec {
      version = "1.56";
      src = prev.fetchurl {
        url = "https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-${version}.tar.bz2";
        hash = "sha256-gsPS3rStlq05Jdb58ST+cgVxYFWrUOKREW7yeXXRacA=";
      };
    });

    libgcrypt = prev.libgcrypt.overrideAttrs (old: rec {
      version = "1.12.0";
      src = prev.fetchurl {
        url = "https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-${version}.tar.bz2";
        hash = "sha256-AxFFTmeBibrWKn6UAqndeTAl7/9udEmJhhbi/HXg9PU=";
      };
    });

    gnupg = prev.gnupg.overrideAttrs (old: rec {
      version = "2.5.19";
      src = prev.fetchurl {
        url = "https://www.gnupg.org/ftp/gcrypt/gnupg/gnupg-${version}.tar.bz2";
        hash = "sha256-ciqopCbdm0Tg0ZS3O/7jo+YX1lZ0zU0dBi5t8p8XiMY=";
      };
	  patches = [];
    });
  };
  
  pkgs = import <nixpkgs> { overlays = [ rust_overlay ]; };

  gnupg_pkgs = import <nixpkgs> { overlays = [ gnupg_overlay ]; };

  rust-toolchain = pkgs.rust-bin.stable.latest.default.override {
    extensions = [ "rust-src" "rustfmt" "clippy" ];
  };
in
pkgs.mkShell {
  name = "bouclier-bleu-dev";

  nativeBuildInputs = with pkgs; [
    # Rust Toolchain
	rust-toolchain
	shfmt
	rust-code-analysis

    # C/eBPF Compilers and Tools
	bpftools jq
    clang
    llvm
    pkg-config
	incus
  ] ++ (if useCustomGnuPG then [ gnupg_pkgs.gnupg ] else [ gnupg ]);

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

	# Bypass the Nix cc-wrapper for direct eBPF compilation
    export BPF_CLANG="${pkgs.llvmPackages.clang-unwrapped}/bin/clang"
    export BPF_CFLAGS="-I${pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include"

    # Gnupg
    export GNUPGHOME=$PWD/.gnupg-bouclier
    mkdir -p $GNUPGHOME ; chmod 700 $GNUPGHOME
    gpgconf --kill all
    gpg-agent --daemon

    echo "* Welcome to the bouclier-bleu NixOS dev shell!"
    echo "------------------------------------------------"
    echo "Rust version:  $(rustc --version)"
    echo "Clang version: $(clang --version | head -n 1)"
    echo "Gnupg version: $(gpg --version | head -n 1)"
    echo "------------------------------------------------"
    echo "Run: cargo build"
  '';
}
