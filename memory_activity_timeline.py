# Memory Activity Timeline
# 
# l'objectif est de reconstruire une timeline comportementale depuis un dump de la mémoire
# 
# Valeur ajoutée:
#   -> Fusionne plusieurs sources mémoire dans une timeline unique
#   -> Permet une analyse chronologique rapide
#   -> Facilite le triage forensic et l'investigation d'incidents
#
# Limites:
#   -> Les événements proviennent uniquement de la mémoire volatile
#   -> Certaines structures peuvent être corrompues ou incomplètes
#   -> Une DLL affichée n'indique pas forcément une activité malveillante
#
# Sortie JSON:
#   {
#       "timeline": [
#           {
#               "timestamp": "...",
#               "category": "...",
#               "pid": ...,
#               "process": "...",
#               "description": "..."
#           }
#       ]
#   }
# Commandes à utiliser:
#   python vol.py -f "dump.raw" windows.memory_activity_timeline --json-output timeline.json


# Import des modules nécessaires qui vont etre utilisés par les methodes ci-dessous 
import datetime
import json
import logging
from typing import Any, Dict, Iterator, List, Optional, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

WIN_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)

# Convertit une valeur Volatility ou Windows en entier de manière robuste
# Certains objets Volatility exposent la valeur dans un attribut QuadPart
def _to_int(value: Any) -> int:
    try:
        if hasattr(value, "QuadPart"):
            return int(value.QuadPart)
        return int(value)
    except Exception:
        # En forensic mémoire, certaines structures peuvent être invalides ou corrompues
        # On retourne 0 pour éviter de faire planter tout le plugin
        return 0

# Convertit un timestamp Windows FILETIME ou une date Volatility en datetime 
def filetime_to_dt(value: Any) -> Optional[datetime.datetime]:
    """Converts Windows FILETIME or Volatility datetime-like values to UTC datetime."""
    if value is None:
        return None
    # Si Volatility renvoie déjà un objet datetime, on normalise simplement en UTC
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=datetime.timezone.utc)
        return value.astimezone(datetime.timezone.utc)
    # Sinon, on tente d'interpréter la valeur comme un FILETIME brut
    raw = _to_int(value)
    if raw <= 0:
        return None

    try:
        return WIN_EPOCH + datetime.timedelta(microseconds=raw // 10)
    except Exception:
        return None

# Formate une date pour l'affichage dans le tableau Volatility et dans le JSON
def dt_to_str(dt: Optional[datetime.datetime]) -> str:
    if not dt:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

# Récupère le nom d'un processus en gérant les cas où l'objet mémoire est partiellement lisible
def safe_process_name(proc: Any) -> str:
    try:
        return utility.array_to_string(proc.ImageFileName)
    except Exception:
        try:
            return proc.ImageFileName.cast(
                "string",
                max_length=proc.ImageFileName.vol.count,
                errors="replace",
            )
        except Exception:
            return "unknown"





# Représentation interne d'un événement de timeline
# Cette classe uniformise les événements de sources différentes : processus, threads, DLL
class TimelineEvent:
    def __init__(
        self,
        timestamp: Optional[datetime.datetime],
        category: str,
        pid: int,
        process: str,
        description: str,
        extra: Optional[Dict[str, Any]] = None,
    ):
        self.timestamp = timestamp or datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
        self.category = category
        self.pid = pid
        self.process = process
        self.description = description
        self.extra = extra or {}
    # Convertit l'événement en dictionnaire sérialisable en JSON
    def to_dict(self) -> Dict[str, Any]:
        data = {
            "timestamp": dt_to_str(self.timestamp),
            "category": self.category,
            "pid": self.pid,
            "process": self.process,
            "description": self.description,
        }
        # Ajoute les champs additionnels sans modifier la structure commune
        data.update(self.extra)
        return data
    # Permet de trier directement une liste de TimelineEvent par timestamp
    def __lt__(self, other: "TimelineEvent") -> bool:
        return self.timestamp < other.timestamp

# Classe principale du plugin
# Elle hérite de PluginInterface afin d'être exécutable via vol.py
class MemTimeline(interfaces.plugins.PluginInterface):

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    # Déclare les paramètres acceptés par le plugin
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Only include these PIDs",
                optional=True,
            ),
            requirements.StringRequirement(
                name="json-output",
                description="Optional JSON output path",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="include-threads",
                description="Include ETHREAD creation events",
                optional=True,
                default=True,
            ),
            requirements.BooleanRequirement(
                name="include-dlls",
                description="Include loaded DLL events from process loader lists",
                optional=True,
                default=True,
            ),
        ]
    # Construit le filtre PID utilisé par pslist
    def _pid_filter(self):
        pids = self.config.get("pid", None)
        return pslist.PsList.create_pid_filter(pids)
    # Retourne l'itérateur des processus Windows présents dans le dump mémoire
    def _processes(self):
        return pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=self._pid_filter(),
        )
    # Collecte les événements de création et de fin des processus
    def _collect_process_events(self) -> List[TimelineEvent]:
        events: List[TimelineEvent] = []

        for proc in self._processes():
            try:
                pid = int(proc.UniqueProcessId)
                ppid = int(proc.InheritedFromUniqueProcessId)
                name = safe_process_name(proc)
                # Événement de création du processus
                create_dt = filetime_to_dt(proc.CreateTime)
                if create_dt:
                    events.append(
                        TimelineEvent(
                            create_dt,
                            "PROCESS_CREATE",
                            pid,
                            name,
                            f"Process created; PPID={ppid}",
                            {"ppid": ppid, "offset": hex(proc.vol.offset)},
                        )
                    )
                # Événement de terminaison du processus si ExitTime est disponible
                exit_dt = filetime_to_dt(proc.ExitTime)
                if exit_dt:
                    events.append(
                        TimelineEvent(
                            exit_dt,
                            "PROCESS_EXIT",
                            pid,
                            name,
                            f"Process exited; PPID={ppid}",
                            {"ppid": ppid, "offset": hex(proc.vol.offset)},
                        )
                    )
            except exceptions.InvalidAddressException:
                continue
            except Exception as exc:
                vollog.debug("Process collection error: %s", exc)

        return events
    # Collecte les événements de création des threads 
    def _collect_thread_events(self) -> List[TimelineEvent]:
        events: List[TimelineEvent] = []
        kernel = self.context.modules[self.config["kernel"]]

        for proc in self._processes():
            try:
                pid = int(proc.UniqueProcessId)
                name = safe_process_name(proc)

                for thread in proc.ThreadListHead.to_list(
                    symbol_type=kernel.symbol_table_name + "!_ETHREAD",
                    member="ThreadListEntry",
                ):
                    try:
                        tid = int(thread.Cid.UniqueThread)
                        create_dt = filetime_to_dt(thread.CreateTime)
                        if create_dt:
                            events.append(
                                TimelineEvent(
                                    create_dt,
                                    "THREAD_CREATE",
                                    pid,
                                    name,
                                    f"Thread created; TID={tid}",
                                    {"tid": tid},
                                )
                            )
                    except exceptions.InvalidAddressException:
                        continue
                    except Exception:
                        continue
            except exceptions.InvalidAddressException:
                continue
            except Exception as exc:
                vollog.debug("Thread collection error: %s", exc)

        return events
    # Collecte les événements de chargement de DLL depuis les listes du loader utilisateur
    def _collect_dll_events(self) -> List[TimelineEvent]:
        events: List[TimelineEvent] = []

        for proc in self._processes():
            try:
                pid = int(proc.UniqueProcessId)
                name = safe_process_name(proc)

                # Si le champ LoadTime d'une DLL n'est pas disponible
                # on utilise la date de création du processus comme approximation
                fallback_dt = filetime_to_dt(proc.CreateTime)

                try:
                    proc.add_process_layer()
                except Exception:
                    pass

                for entry in proc.load_order_modules():
                    try:
                        dll_name = entry.BaseDllName.get_string()
                        dll_path = entry.FullDllName.get_string()
                        dll_base = int(entry.DllBase)

                        load_dt = None
                        if hasattr(entry, "LoadTime"):
                            load_dt = filetime_to_dt(entry.LoadTime)

                        if not load_dt:
                            load_dt = fallback_dt

                        if load_dt:
                            events.append(
                                TimelineEvent(
                                    load_dt,
                                    "DLL_LOAD",
                                    pid,
                                    name,
                                    f"DLL loaded: {dll_name}",
                                    {
                                        "dll_name": dll_name,
                                        "dll_path": dll_path,
                                        "dll_base": hex(dll_base),
                                    },
                                )
                            )
                    except exceptions.InvalidAddressException:
                        continue
                    except Exception:
                        continue
            except exceptions.InvalidAddressException:
                continue
            except Exception as exc:
                vollog.debug("DLL collection error: %s", exc)

        return events
    # Exporte les événements collectés dans un fichier JSON
    def _export_json(self, events: List[TimelineEvent], path: str) -> None:
        data = {"timeline": [event.to_dict() for event in events]}
        with open(path, "w", encoding="utf-8") as fout:
            json.dump(data, fout, indent=2, ensure_ascii=False)
    # Générateur appelé par Volatility pour alimenter le TreeGrid ligne par ligne
    def _generator(self) -> Iterator[Tuple[int, Tuple[str, str, int, str, str]]]:
        events: List[TimelineEvent] = []
        # Les processus sont toujours collectés, car ils constituent la base de la timeline
        events.extend(self._collect_process_events())

        # Collecte optionnelle des threads
        if self.config.get("include-threads", True):
            events.extend(self._collect_thread_events())

        # Collecte optionnelle des DLL chargées
        if self.config.get("include-dlls", True):
            events.extend(self._collect_dll_events())

        # Trie chronologique global de tous les événements collectés
        events.sort()

        # Export JSON si l'utilisateur a fourni --json-output.
        json_output = self.config.get("json-output", None)
        if json_output:
            self._export_json(events, json_output)

        # Rend chaque événement dans le format attendu par TreeGrid
        for event in events:
            yield (
                0,
                (
                    dt_to_str(event.timestamp),
                    event.category,
                    int(event.pid),
                    str(event.process),
                    str(event.description),
                ),
            )
    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Timestamp", str),
                ("Category", str),
                ("PID", int),
                ("Process", str),
                ("Description", str),
            ],
            self._generator(),
        )
