# Test server (presubuntu)

Full VM reset lives in the **Homelab** repo. Installing and testing PVFS on that host is documented in **[docs/INSTALL.md](../docs/INSTALL.md)** (Option B).

## Reset to a clean Ubuntu host

```bash
cd ~/Projects/Homelab
./scripts/presubuntu-reset.sh
```

Type `presubuntu` when prompted. This recreates Proxmox VM 101 (fresh Ubuntu 24.04, user `chris`, no legacy Docker stack).

Prerequisites: VPN to `192.168.0.184`, Terraform `.env.terraform` on Homelab — see [PRESUBUNTU_RESET.md](https://github.com/christcb03/Homelab/blob/main/docs/PRESUBUNTU_RESET.md).

## After reset — install PVFS

```bash
cd ~/Projects/phrasevault/deploy/ansible
cp inventory.example.ini inventory.ini
ansible-galaxy collection install ansible.posix
ansible-playbook -i inventory.ini pipeline.yml
```

Then SSH in and follow the manual test section in [docs/INSTALL.md](../docs/INSTALL.md).

## Legacy stack

The v0.0 Docker prototype is under `v0.0-concept/`. Do not redeploy it unless you intentionally want the old MediaForest stack.
