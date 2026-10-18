"""
FalkorDB connection wrapper with lazy singleton pooling.
"""
from typing import Any, Dict, Optional
from falkordb import FalkorDB

from app.config import get_settings


class GraphClient:
    def __init__(self):
        self.settings = get_settings()
        self._client: Optional[FalkorDB] = None
        self._graph = None

    def connect(self):
        if self._client is None:
            timeout_sec = getattr(self.settings, "falkordb_timeout_ms", 5000) / 1000.0
            self._client = FalkorDB(
                host=self.settings.falkordb_host,
                port=self.settings.falkordb_port,
                socket_timeout=timeout_sec,
            )
            self._graph = self._client.select_graph(self.settings.falkordb_graph_name)
        return self._graph

    def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> Any:
        graph = self.connect()
        return graph.query(query, params or {})

    def ping(self) -> bool:
        try:
            self.connect()
            self.execute_query("RETURN 1 AS ping")
            return True
        except Exception:
            return False


_graph_client: Optional[GraphClient] = None


def get_graph_client() -> GraphClient:
    global _graph_client
    if _graph_client is None:
        _graph_client = GraphClient()
    return _graph_client
