_: {
  perSystem =
    {
      lib,
      pkgs,
      mkCi,
      unstablePkgs,
      ensureAtRepositoryRoot,
      ...
    }:
    let
      pkgsDeps = with pkgs; [ pkg-config ];
      nodeDeps = with unstablePkgs; [
        vips
        nodePackages_latest.nodejs
      ];
      combinedDeps = pkgsDeps ++ nodeDeps;
      packageJSON = lib.importJSON ./package.json;
    in
    {
      packages = {
        docs = mkCi false (
          unstablePkgs.buildNpmPackage {
            npmDepsHash = "sha256-v2rwxCCKmbtwxAynUryTigfg0V4cmARh6HgfKTwFQds=";
            src = ./.;
            srcs = [
              ./.
              ./../versions/.
            ];
            sourceRoot = "docs";
            pname = packageJSON.name;
            inherit (packageJSON) version;
            nativeBuildInputs = combinedDeps;
            buildInputs = combinedDeps;
            installPhase = ''
              mkdir -p $out
              cp -r ./dist/* $out
            '';
            doDist = false;
            PUPPETEER_SKIP_DOWNLOAD = 1;
            ASTRO_TELEMETRY_DISABLED = 1;
            NODE_OPTIONS = "--no-warnings";
          }
        );
      };

      apps = {
        docs-dev-server = {
          type = "app";
          program = pkgs.writeShellApplication {
            name = "docs-dev-server";
            runtimeInputs = combinedDeps;
            text = ''
              ${ensureAtRepositoryRoot}
              cd docs/

              export PUPPETEER_SKIP_DOWNLOAD=1 
              npm install
              npm run dev
            '';
          };
        };
        docs-check = {
          type = "app";
          program = pkgs.writeShellApplication {
            name = "docs-check";
            runtimeInputs = combinedDeps;
            text = ''
              ${ensureAtRepositoryRoot}
              biome check docs --error-on-warnings --write --unsafe

              nix fmt

              cd docs/

              npm_config_yes=true npx astro check
              npm_config_yes=true npx astro build

              nix build .\#checks.${pkgs.system}.spellcheck --print-build-logs
            '';
          };
        };
        deploy-docs-ipfs = {
          type = "app";
          program = pkgs.writeShellApplication {
            name = "deploy-docs-ipfs";
            runtimeInputs = combinedDeps;
            text = ''
              ${ensureAtRepositoryRoot}
              cd docs/

              export PUPPETEER_SKIP_DOWNLOAD=1 
              nix build .#docs
              npm_config_yes=true npx @fleek-platform/cli sites deploy
            '';
          };
        };
      };
    };
}
