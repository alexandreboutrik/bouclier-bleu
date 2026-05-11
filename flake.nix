{
  description = "Bouclier Bleu - Modular NGAV and EDR for Linux";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      
      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; });
    in {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgsFor.${system};
		  referenceBtf = pkgs.fetchurl {
            url = "https://raw.githubusercontent.com/libbpf/vmlinux.h/refs/heads/main/include/x86/vmlinux_6.19.h";
            hash = "sha256-EGyensfjwZSPFV80q2tmerX27HHlZ3boe9uuNkP8J4I=";
          };

        in {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "bouclier-bleu";
            version = "0.10.0";

            src = ./.;

            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            # Build-time dependencies
            nativeBuildInputs = with pkgs; [
			  bpftools
              pkg-config
              clang
              llvm
              rustPlatform.bindgenHook # sets up LIBCLANG_PATH for libbpf-rs
            ];

            # Linking dependencies
            buildInputs = with pkgs; [
              elfutils # libelf
              zlib
              libbpf
              linuxHeaders
            ];

            # Disable Nix's default C compiler hardening flags.
            # eBPF compilation targets a very restricted VM and fails if 
            # standard user-space stack protectors are injected.
            hardeningDisable = [ "all" ];

            # Map the exact clang and include paths needed by build.rs
            BPF_CLANG = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";
            BPF_CFLAGS = "-I${pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include";

			VMLINUX_H_PATH = "${referenceBtf}";
            
            # Nix builds are performed in a strict, unprivileged sandbox
			# without network access.
            # Since Bouclier Bleu requires an Incus VM and root capabilities
			# (CAP_BPF) for its test suites we must disable the sandbox tests.
            doCheck = false; 

			# Manipulate the final binaries after Cargo installs them
            postInstall = ''
              # Rename binaries to match your project branding
              mv $out/bin/core $out/bin/bouclier-bleu-core
              mv $out/bin/cli $out/bin/bouclier-bleu-cli
              rm -f $out/bin/xtask
            '';

            meta = with pkgs.lib; {
              description = "Next-Generation Antivirus (NGAV) and Endpoint Detection and Response (EDR) system";
              homepage = "https://github.com/alexandreboutrik/bouclier-bleu";
              license = with licenses; [ gpl2Only asl20 ];
              maintainers = [ "alexandreboutrik" ];
              platforms = platforms.linux;
            };
          };
        });

	  # Applications definition for 'nix run'
	  apps = forAllSystems (system: {
        cli = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/bouclier-bleu-cli";
        };
        core = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/bouclier-bleu-core";
        };
        
        # Make the CLI the default if a specific app isn't requested
        default = self.apps.${system}.cli; 
      });

      # Provides a default devShell mapping to shell.nix
      devShells = forAllSystems (system: {
        default = import ./shell.nix { }; 
      });
    };
}
