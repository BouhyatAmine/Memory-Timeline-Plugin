# memory_activity_timeline — Timeline forensique d'activité mémoire Windows

> Projet réalisé par : **Mohammed Amine BOUHYAT**, **Zoubir BEL AIACHI**, **Ziad ESSAIDI**, **Mamadou Tanou DIALLO**

Ce projet est composé de deux scripts complémentaires destinés à l'analyse
forensique de dumps mémoire Windows avec **Volatility 3** :

| Fichier | Rôle |
|---|---|
| `memory_activity_timeline.py` | Plugin Volatility 3 qui extrait une timeline d'événements (création de processus, threads, chargement de DLL) depuis un dump mémoire `.raw` |
| `mem_timeline_html.py` | Script autonome qui transforme le JSON produit par le plugin en un rapport HTML interactif (filtrage, recherche, regroupement par processus) |

---

## 1. `memory_activity_timeline.py` — Plugin Volatility 3

### Prérequis

- Volatility 3installé et fonctionnel
- Un dump mémoire Windows (`.raw`, `.vmem`, `.dmp`, etc.)

### Installation

Copier le fichier dans le dossier des plugins Windows de Volatility 3 :

volatility3/plugins/windows/memory_activity_timeline.py

### Ce que fait le plugin

Le plugin parcourt la liste des processus (`pslist`) du dump mémoire et
construit une timeline chronologique en combinant trois sources d'événements :

| Catégorie | Source | Description |
|---|---|---|
| `PROCESS_CREATE` | `EPROCESS.CreateTime` | Horodatage de création d'un processus |
| `PROCESS_EXIT` | `EPROCESS.ExitTime` | Horodatage de fin d'un processus (si terminé) |
| `THREAD_CREATE` | `ETHREAD.CreateTime` (liste `ThreadListHead`) | Création de chaque thread d'un processus |
| `DLL_LOAD` | `load_order_modules()` (PEB / loader list) | Chargement de chaque DLL dans l'espace du processus |

Les timestamps Windows **FILETIME** (100 ns depuis le 1er janvier 1601) sont
convertis en `datetime` UTC lisibles via `filetime_to_dt()`.

Tous les événements sont ensuite triés chronologiquement (`events.sort()`,
grâce à `TimelineEvent.__lt__`) avant d'être affichés ou exportés.

### Exécution

python vol.py -f "dump.raw" windows.memory_activity_timeline.MemTimeline

### Options disponibles

| Option | Description |
|---|---|
| `--pid <PID> [<PID> ...]` | Limite l'analyse à un ou plusieurs PID précis |
| `--json-output <fichier.json>` | Exporte la timeline au format JSON (nécessaire pour générer le rapport HTML) |
| `--include-threads` *(actif par défaut)* | Inclut ou non les événements `THREAD_CREATE` |
| `--include-dlls` *(actif par défaut)* | Inclut ou non les événements `DLL_LOAD` |

# Exemples

### Timeline complète, affichée dans la console
`python vol.py -f "dump.raw" windows.memory_activity_timeline.MemTimeline`

### Timeline limitée à un processus, exportée en JSON
`python vol.py -f "dump.raw" windows.memory_activity_timeline.MemTimeline --pid 1234 --json-output timeline.json`

### Sans les événements de threads (timeline plus légère)
`python vol.py -f "dump.raw" windows.memory_activity_timeline.MemTimeline --include-threads False --json-output timeline.json`

# Valeur ajoutée

- **Fusionne plusieurs sources mémoire** (processus, threads, DLL) en une
  timeline unique et chronologique, sans croiser manuellement plusieurs
  plugins Volatility.
- **Permet une analyse chronologique rapide**, utile pour repérer des
  séquences d'événements suspectes.
- **Facilite le triage forensic** grâce à un export JSON et un rapport
  HTML interactif directement exploitables.

# Limites

- Les événements proviennent **uniquement de la mémoire volatile** au
  moment du dump : toute activité déjà effacée de la RAM n'apparaît pas.
- Certaines structures noyau **peuvent être corrompues ou incomplètes**
  (rootkit, crash, dump partiel), entraînant des événements manquants.
- Une **DLL affichée n'indique pas forcément une activité malveillante** :
  une analyse complémentaire reste nécessaire avant toute conclusion.

---

## 2. `mem_timeline_html.py` — Générateur de rapport HTML

### Prérequis

- Python 3.8+ (aucune dépendance externe : seulement la bibliothèque standard)
- Un fichier `timeline.json` produit par `memory_activity_timeline.py`

### Exécution

python mem_timeline_html.py timeline.json

Par défaut, le rapport est généré à côté du fichier source :
`timeline.json` → `timeline_report.html`

### Options disponibles

| Option | Description |
|---|---|
| `-o`, `--output <fichier.html>` | Chemin de sortie personnalisé pour le rapport |
| `-t`, `--title "<titre>"` | Titre affiché dans le rapport (ex : nom de l'incident) |

### Exemples

python mem_timeline_html.py timeline.json --output rapport.html
python mem_timeline_html.py timeline.json --title "Incident 2026-06-15"

### Ce que contient le rapport généré

Le fichier `.html` produit est **totalement autonome** (HTML + CSS + JS +
données embarqués dans un seul fichier) : il s'ouvre directement dans un
navigateur, sans serveur ni connexion réseau (à l'exception du chargement
des polices Google Fonts).

Fonctionnalités du rapport :

- **Regroupement par processus** (nom + PID), sections repliables/dépliables
- **Recherche texte libre** (processus, DLL, description, PID...)
- **Filtre par PID** via menu déroulant
- **Filtres par catégorie** (`PROCESS_CREATE`, `PROCESS_EXIT`,
  `THREAD_CREATE`, `DLL_LOAD`) sous forme de pastilles cliquables
- **Plage temporelle globale** affichée dans la barre supérieure
- Boutons **Expand All / Collapse All / Reset**

## Exemple de rapport généré

Le fichier `timeline_report.html` fourni dans ce dépôt est un exemple concret
de rapport généré par le workflow complet décrit ci-dessus. Il a été produit
à partir du dump mémoire d'une **machine virtuelle infectée**, utilisée dans
le cadre du cours d'**analyse de malware**. Il permet de visualiser
directement le rendu du rapport HTML interactif sans avoir à effectuer
l'analyse soi-même.
