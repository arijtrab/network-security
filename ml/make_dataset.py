#!/usr/bin/env python3
"""Génère ml/data/findings_labeled.csv (jeu SYNTHÉTIQUE, écrit à la main puis augmenté).
Colonnes : text, iso, severity, split. Les 2 derniers gabarits de chaque classe sont réservés au test
(formulations jamais vues à l'entraînement) pour éviter une évaluation trop optimiste."""
import csv
import pathlib
import random

T = {  # contrôle ISO -> liste de (gabarit, gravité) ; les 2 derniers = test
 "A.8.21": [("Telnet est activé sur l'équipement", "HIGH"), ("Le service FTP est activé, transfert en clair", "HIGH"),
            ("Administration web en HTTP non chiffré activée", "HIGH"), ("Service TFTP exposé sans authentification", "HIGH"),
            ("Protocole non sécurisé utilisé pour l'administration à distance", "HIGH"),
            ("Service réseau inutile activé (finger, echo, chargen)", "MEDIUM"),
            ("Interface d'administration HTTP accessible sans TLS", "HIGH"), ("Rlogin et rsh actifs sur l'équipement", "HIGH"),
            ("Telnet enabled on the device", "HIGH"), ("Le service de transfert FTP est ouvert", "HIGH")],
 "A.8.20": [("Règle ANY vers ANY autorisée sur le pare-feu", "CRITICAL"), ("Règle permissive autorisant tout le trafic", "CRITICAL"),
            ("Port dangereux ouvert depuis une source large (RDP 3389)", "HIGH"), ("Tous les ports sont ouverts depuis Internet", "CRITICAL"),
            ("Règle de filtrage sans restriction d'adresse source", "MEDIUM"), ("Accès SSH autorisé depuis 0.0.0.0/0", "CRITICAL"),
            ("Ports inutilisés non désactivés sur le switch", "MEDIUM"), ("Politique par défaut en allow au lieu de deny", "HIGH"),
            ("Autorisation de tout le trafic entre toutes les adresses", "CRITICAL"), ("Ports SMB et NetBIOS exposés à Internet", "HIGH")],
 "A.8.22": [("Accès direct d'Internet vers la zone d'administration", "CRITICAL"),
            ("Flux autorisé vers une zone sensible depuis une source large", "CRITICAL"), ("VLAN natif laissé à 1 sur le trunk", "MEDIUM"),
            ("Absence de séparation entre le réseau utilisateurs et serveurs", "HIGH"),
            ("Zone d'administration joignable depuis le réseau invités", "HIGH"),
            ("VLAN de gestion mélangé avec le trafic utilisateurs", "MEDIUM"),
            ("DMZ autorisée à initier des connexions vers le réseau interne", "HIGH"),
            ("Segmentation réseau insuffisante entre zones", "MEDIUM"),
            ("Le réseau de gestion est accessible depuis Internet", "CRITICAL"),
            ("VLAN natif par défaut non modifié sur les trunks", "MEDIUM")],
 "A.5.15": [("Accès administratif ouvert à un réseau trop large", "HIGH"), ("SSH sans restriction d'adresse source", "HIGH"),
            ("Sources autorisées pour l'administration non définies", "HIGH"), ("Compte administrateur partagé entre plusieurs personnes", "MEDIUM"),
            ("Absence de liste de contrôle d'accès sur l'interface de gestion", "HIGH"),
            ("Accès privilégié accordé sans principe du moindre privilège", "MEDIUM"),
            ("Plage d'adresses d'administration plus large qu'un /24", "HIGH"),
            ("Aucune limitation des hôtes autorisés à administrer l'équipement", "HIGH"),
            ("L'administration est permise depuis n'importe quelle adresse", "HIGH"),
            ("Droits d'accès excessifs sur le compte d'exploitation", "MEDIUM")],
 "A.5.17": [("Mot de passe en clair dans le fichier de configuration", "CRITICAL"), ("Secret SNMP stocké en clair dans la configuration", "CRITICAL"),
            ("Clé privée présente dans le dépôt", "CRITICAL"), ("Identifiants codés en dur dans la configuration", "CRITICAL"),
            ("Jeton d'API visible dans le fichier", "CRITICAL"), ("Mot de passe par défaut inchangé sur l'équipement", "HIGH"),
            ("Mot de passe faible ou non chiffré dans la config", "HIGH"), ("Secret partagé RADIUS écrit en clair", "CRITICAL"),
            ("Password found in plain text in config file", "CRITICAL"),
            ("Chaîne de communauté publique définie en dur dans le fichier", "CRITICAL")],
 "A.8.24": [("SSH version 1 autorisée", "HIGH"), ("SNMP v1 ou v2c utilisé sans chiffrement", "HIGH"),
            ("TLS 1.0 accepté pour l'administration", "HIGH"), ("Algorithmes de chiffrement obsolètes activés (DES, RC4)", "HIGH"),
            ("Protocole de routage sans authentification cryptographique", "MEDIUM"), ("Version obsolète du protocole RIP v1", "MEDIUM"),
            ("Hachage MD5 utilisé pour l'authentification", "MEDIUM"), ("Certificat auto-signé expiré sur l'interface web", "MEDIUM"),
            ("Version SSH inférieure à 2 acceptée", "HIGH"), ("Version de protocole obsolète acceptée (SNMPv1)", "HIGH")],
 "A.8.15": [("Journalisation non activée", "MEDIUM"), ("Aucun serveur syslog configuré", "LOW"),
            ("Logs désactivés sur les règles de refus", "LOW"), ("Les événements de sécurité ne sont pas enregistrés", "MEDIUM"),
            ("Absence de journalisation des accès administratifs", "MEDIUM"), ("Journaux non envoyés vers un serveur central", "LOW"),
            ("Niveau de log insuffisant sur le pare-feu", "LOW"), ("Traçabilité des connexions impossible faute de logs", "MEDIUM"),
            ("Logging is disabled on the device", "MEDIUM"), ("Le serveur de journaux distant n'est pas renseigné", "LOW")],
 "A.8.9": [("Délai d'inactivité de session SSH non défini", "MEDIUM"), ("Configuration par défaut du constructeur conservée", "MEDIUM"),
           ("Bannière d'avertissement légal absente", "LOW"), ("Durcissement de l'équipement non appliqué", "MEDIUM"),
           ("Timeout de session trop long sur la console", "MEDIUM"), ("Services par défaut non désactivés lors de la mise en service", "MEDIUM"),
           ("Paramètre de base non conforme à la configuration de référence", "MEDIUM"),
           ("Modification de configuration non documentée ni versionnée", "LOW"),
           ("Session timeout not configured", "MEDIUM"), ("Écart avec la configuration de référence (drift)", "MEDIUM")],
}
DEVICES = ["router01", "firewall01", "switch01", "fw-dmz", "core-sw", "edge-rtr"]


def main():
    random.seed(42)
    rows = []
    for iso, items in T.items():
        for i, (text, sev) in enumerate(items):
            split = "test" if i >= len(items) - 2 else "train"
            for d in DEVICES:
                rows.append((f"{d} : {text}", iso, sev, split))
                rows.append((f"{text} sur {d}", iso, sev, split))
    random.shuffle(rows)
    out = pathlib.Path(__file__).parent / "data" / "findings_labeled.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["text", "iso", "severity", "split"])
        w.writerows(rows)
    print(f"{len(rows)} lignes écrites dans {out}")


if __name__ == "__main__":
    main()
