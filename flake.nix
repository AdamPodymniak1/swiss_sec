{
  description = "SwissSec firmware dev shell (PlatformIO for the ESP32-S3)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.platformio
          ];

          # PlatformIO's own installer tries to fetch/build udev rules and
          # python packages into ~/.platformio at first run, which doesn't
          # play well with the Nix store being read-only / hermetic. Keep
          # its state inside the repo (already gitignored via .pio) instead.
          shellHook = ''
            export PLATFORMIO_CORE_DIR="$PWD/.platformio-core"
            echo "PlatformIO $(pio --version 2>/dev/null || echo '(run: pio --version)') ready."
            echo "Build:  pio run -e esp32s3-atecc-debug"
            echo "Flash:  pio run -e esp32s3-atecc-debug -t upload -t monitor"
            if ! id -nG | grep -qw dialout; then
              echo "NOTE: your user is not in the 'dialout' group - uploading over"
              echo "      USB serial will fail with a permissions error until you add"
              echo "      users.users.<you>.extraGroups = [ \"dialout\" ]; in your NixOS"
              echo "      config and re-login (or just: sudo pio run -t upload)."
            fi
          '';
        };
      });
}
