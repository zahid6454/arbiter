"""Kubernetes collector — kubectl-based pod-level enrichment for GKE investigations."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess

logger = logging.getLogger(__name__)


def _safe_int(value: str, default: int = 0) -> int:
    """Parse an integer, returning default on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def kubectl_context_name(project: str, location: str, cluster: str) -> str:
    """Construct the expected kubeconfig context name for a GKE cluster."""
    return f"gke_{project}_{location}_{cluster}"


class KubernetesCollector:
    """Collects pod-level context via kubectl for GKE investigations.

    Auto-discovers kubectl from PATH and kubeconfig contexts. Does not
    extend the Collector ABC — kubectl is a different tool with different
    auth (kubeconfig, not API keys).
    """

    def __init__(self, context: str, namespace: str = "default"):
        self.context = context
        self.namespace = namespace

    def is_configured(self) -> bool:
        """Check if kubectl is installed and the context exists."""
        if not shutil.which("kubectl"):
            return False
        result = self._run_kubectl(
            ["config", "get-contexts", self.context, "--no-headers"],
            timeout=5,
        )
        return result is not None

    def _run_kubectl(self, args: list[str], timeout: int = 15) -> str | None:
        """Run a kubectl command. Returns stdout or None on failure."""
        try:
            result = subprocess.run(
                ["kubectl", f"--context={self.context}", *args],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None

    def collect_pod_context(self, service_name: str = "") -> dict | None:
        """Collect pod-level context. Returns None if unavailable."""
        if not self.is_configured():
            return None

        probe = self._run_kubectl(["cluster-info"], timeout=10)
        if probe is None:
            return None

        result: dict = {
            "context": self.context,
            "namespace": self.namespace,
        }

        nodes = self._collect_nodes()
        if nodes is not None:
            result["nodes"] = nodes

        pdb = self._collect_pdb()
        if pdb is not None:
            result["pdb"] = pdb

        pods = self._collect_pods(service_name)
        if pods is not None:
            result["pods"] = pods

        events = self._collect_events()
        if events is not None:
            result["events"] = events

        return result

    def _collect_nodes(self) -> dict | None:
        output = self._run_kubectl(
            [
                "get",
                "nodes",
                "--sort-by=.metadata.creationTimestamp",
                "-o",
                "custom-columns=NAME:.metadata.name,AGE:.metadata.creationTimestamp,STATUS:.status.conditions[-1].type",
                "--no-headers",
            ]
        )
        if output is None:
            return None

        nodes = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                nodes.append({"name": parts[0], "created": parts[1]})

        if not nodes:
            return {"count": 0, "all_recent": False}

        from datetime import UTC, datetime

        now = datetime.now(UTC)
        ages_hours = []
        for node in nodes:
            try:
                created = datetime.fromisoformat(node["created"].replace("Z", "+00:00"))
                age_h = (now - created).total_seconds() / 3600
                ages_hours.append(age_h)
            except (ValueError, TypeError):
                pass

        return {
            "count": len(nodes),
            "min_age": f"{min(ages_hours):.1f}h" if ages_hours else None,
            "max_age": f"{max(ages_hours):.1f}h" if ages_hours else None,
            "all_recent": all(a < 6 for a in ages_hours) if ages_hours else False,
        }

    def _collect_pdb(self) -> dict | None:
        output = self._run_kubectl(
            [
                "get",
                "pdb",
                f"-n={self.namespace}",
                "-o",
                "custom-columns=NAME:.metadata.name,MIN:.spec.minAvailable,MAX:.spec.maxUnavailable,SELECTOR:.spec.selector.matchLabels",
                "--no-headers",
            ]
        )
        if output is None:
            return None

        if not output or output.strip().startswith("No resources found"):
            return {"configured": False, "policies": []}

        policies = []
        for line in output.splitlines():
            parts = line.split(None, 3)
            if len(parts) >= 1:
                policies.append(
                    {
                        "name": parts[0],
                        "min_available": parts[1] if len(parts) > 1 else None,
                        "max_unavailable": parts[2] if len(parts) > 2 else None,
                    }
                )

        return {"configured": len(policies) > 0, "policies": policies}

    def _collect_pods(self, service_name: str) -> dict | None:
        label_filter = f"-l=app={service_name}" if service_name else ""
        args = [
            "get",
            "pods",
            f"-n={self.namespace}",
            "-o",
            "custom-columns=NAME:.metadata.name,STATUS:.status.phase,RESTARTS:.status.containerStatuses[0].restartCount,AGE:.metadata.creationTimestamp",
            "--no-headers",
        ]
        if label_filter:
            args.append(label_filter)

        output = self._run_kubectl(args)
        if output is None:
            return None

        pods = []
        total_restarts = 0
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                restarts = _safe_int(parts[2]) if len(parts) > 2 else 0
                total_restarts += restarts
                pods.append({"name": parts[0], "status": parts[1], "restarts": restarts})

        status_counts: dict[str, int] = {}
        for pod in pods:
            s = pod["status"]
            status_counts[s] = status_counts.get(s, 0) + 1

        return {
            "total": len(pods),
            "status": status_counts,
            "restart_count": total_restarts,
        }

    def _collect_events(self) -> list[dict] | None:
        output = self._run_kubectl(
            [
                "get",
                "events",
                f"-n={self.namespace}",
                "--sort-by=.lastTimestamp",
                "--field-selector=type!=Normal",
                "-o",
                "custom-columns=TYPE:.type,REASON:.reason,MESSAGE:.message,COUNT:.count,LAST:.lastTimestamp",
                "--no-headers",
            ]
        )
        if output is None:
            return None

        events = []
        for line in output.splitlines():
            match = re.match(r"^(\S+)\s+(\S+)\s+(.+?)\s+(\d+)\s+(\S+)$", line)
            if match:
                events.append(
                    {
                        "type": match.group(1),
                        "reason": match.group(2),
                        "message": match.group(3).strip()[:200],
                        "count": int(match.group(4)),
                        "last_seen": match.group(5),
                    }
                )

        return events[-20:] if events else []
