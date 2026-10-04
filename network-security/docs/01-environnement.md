# 1. Environnement : une VM VMware + VS Code

## 1.1 Réparer la virtualisation (une fois)
1. BIOS/UEFI : activer **Intel VT-x** (ou **AMD-V / SVM**).
2. Windows : *Activer ou désactiver des fonctionnalités* → décocher **Hyper-V**, **Plateforme de l'hyperviseur Windows**, **Plateforme de machine virtuelle**, **Sandbox**.
3. *Sécurité Windows → Sécurité de l'appareil → Isolation du noyau* : désactiver **Intégrité de la mémoire**.
4. Terminal administrateur : `bcdedit /set hypervisorlaunchtype off`, puis redémarrer.
5. Vérifier : VMware Workstation démarre une VM sans message « VT-x non disponible ».

## 1.2 Créer la VM
Ubuntu Server 24.04 · 4 vCPU · 6–8 Go RAM · 40–60 Go de disque · réseau **NAT** (ou « Bridged »).
À l'installation : cocher *OpenSSH server*. Noter l'IP : `ip a`.

## 1.3 Installer les outils (sur la VM)
```bash
sudo apt update && sudo apt install -y git curl make python3-venv python3-pip docker.io docker-compose-v2
sudo usermod -aG docker $USER && newgrp docker
git clone <URL-de-votre-projet> && cd network-security
make install && source .venv/bin/activate && make test
```
Optionnel : le binaire **gitleaks** (releases GitHub) pour le job `secrets-gitleaks`.

## 1.4 VS Code depuis votre PC (Remote-SSH)
1. Installer VS Code puis l'extension **Remote - SSH** (Microsoft).
2. `Ctrl+Maj+P` → *Remote-SSH: Add New SSH Host* → `ssh utilisateur@IP-DE-LA-VM`.
3. *Connect to Host* : le terminal, Python, Docker et Git s'exécutent sur la VM.
4. Extensions utiles *sur la VM* : Python, YAML (Red Hat), GitLab Workflow, Docker.
5. (Recommandé) clé SSH : `ssh-keygen -t ed25519` sur le PC, puis `ssh-copy-id utilisateur@IP`.

## 1.5 Runner GitLab sur la VM (sert au pipeline ET au déploiement dans le lab)
1. GitLab → projet → *Settings → CI/CD → Runners → New project runner* : tag `lab`, cocher *Run untagged jobs* si besoin → copier le **jeton**.
2. Sur la VM (voir la documentation officielle « Install GitLab Runner » si la commande a changé) :
```bash
curl -L "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh" | sudo bash
sudo apt install -y gitlab-runner
sudo gitlab-runner register --url https://gitlab.com --token <JETON> --executor shell
sudo usermod -aG docker gitlab-runner && sudo systemctl restart gitlab-runner
```
3. Vérifier : le runner apparaît en vert dans *Settings → CI/CD → Runners*.

Variante sans runner local : retirer `tags: [lab]` de `.gitlab-ci.yml` pour utiliser les runners partagés de gitlab.com (le déploiement passera alors en mode local, sans conteneurs ; certains comptes gratuits demandent une vérification d'identité pour les runners partagés).
