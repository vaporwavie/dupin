# rustc is wrapped as nixpkgs wraps its own, so the NIX_RUSTFLAGS both builders extend still
# reach it. The frontend flags live here rather than in Cargo's configuration so that Hawk's
# stable rustc, which rejects them, never sees them; rustc also rejects them given twice.
{
  lib,
  rust-bin,
  runCommand,
  makeWrapper,
}:
let
  toolchain = rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;
  frontendRustflags = "-Zunstable-options --jobs-frontend=0";
in
runCommand "${toolchain.name}-wrapped"
  {
    nativeBuildInputs = [ makeWrapper ];
    passthru = {
      inherit (toolchain) targetPlatforms tier1TargetPlatforms badTargetPlatforms;
      inherit frontendRustflags;
      unwrapped = toolchain;
    };
  }
  ''
    mkdir -p $out/bin
    ln -s ${toolchain}/bin/* $out/bin/
    # The C compiler and libiconv the toolchain propagates.
    ln -s ${toolchain}/nix-support $out/nix-support
    rm $out/bin/rustc
    makeWrapper ${toolchain}/bin/rustc $out/bin/rustc \
      --add-flags ${lib.escapeShellArg frontendRustflags} \
      --append-flags '$NIX_RUSTFLAGS'
  ''
