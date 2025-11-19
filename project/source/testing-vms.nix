{
  pkgs ? import <nixpkgs> {} 
}:

let
  makeVM = id: pkgs.nixosTest {
    name = "vm-${toString id}";
    nodes = {
      node = { config, pkgs, ... }: {
        services.openssh.enable = true;
        environment.systemPackages = with pkgs; [
          python3
          git
        ];

        networking.hostName = "node-${toString id}";
      };
    };

    testScript = ''
      start_all();
    '';
  };
in
{
  vms = builtins.listToAttrs (map (id: {
    name = "vm-${toString id}";
    value = makeVM id;
  }) (builtins.genList (x: x) 10));
}

