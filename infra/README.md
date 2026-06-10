# Test server (presubuntu)

Full VM reset and bootstrap live in the **Homelab** repo — presubuntu is already defined there as Proxmox VM **101** via Terraform.

## Reset presubuntu to a clean PVFS test host

```bash
cd ~/Projects/Homelab
./scripts/presubuntu-reset.sh
```

That script:

1. Terraform **destroy + apply** on `proxmox_virtual_environment_vm.prodlab_pres_ubuntu` (fresh Ubuntu 24.04)
2. Waits for SSH on `presubuntu-vpn` (`192.168.0.184`)
3. Runs Ansible `playbooks/presubuntu_reset.yml` — `/opt/pvfs/data`, Rust toolchain, **no Docker / no legacy stack**

See [Homelab/docs/PRESUBUNTU_RESET.md](https://github.com/christcb03/Homelab/blob/main/docs/PRESUBUNTU_RESET.md) for prerequisites (Terraform `.env.terraform`, VPN, DHCP reservation).

## Legacy Docker stack

The v0.0 concept PhraseVault + MediaForest deploy is under `v0.0-concept/`. To put that back on presubuntu after a reset, use Homelab `playbooks/presubuntu.yml` — separate from the PVFS reset flow.
