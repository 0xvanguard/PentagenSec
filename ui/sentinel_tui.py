#!/usr/bin/env python3
"""
pentagensec v4.0 Sentinel TUI
NIST: Timeline interactivo + Chain-of-custody + FP feedback
Framework: Textual 0.66.0
"""
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Grid
from textual.widgets import Header, Footer, DataTable, Log, Static, Button, Label
from textual.binding import Binding
from textual.reactive import reactive
from textual.message import Message
from datetime import datetime
import asyncio

from core.sigma_compiler import SigmaDuckDB
from core.graph_enrich import Neo4jEnricher
from core.active_learning import FPLearner
from core.consensus import AsymmetricConsensus

class SentinelTUI(App):
    """v4.0: TUI para SOC L4. Hotkeys: q=quit, f=mark FP, r=refresh"""

    CSS = """
    Screen {
        layout: grid;
        grid-size: 2;
        grid-columns: 3fr 2fr;
        grid-rows: 3fr 2fr;
    }
    #timeline { border: solid green; row-span: 2; }
    #killchain { border: solid red; }
    #details { border: solid blue; }
    #controls { border: solid yellow; height: 3; dock: bottom; }
    DataTable { height: 100%; }
   .title { text-style: bold; padding: 0 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("r", "refresh", "Refresh"),
        Binding("f", "mark_false_positive", "Mark FP"),
        Binding("enter", "drill_down", "Details"),
    ]

    findings = reactive([])
    selected_event_id = reactive(None)

    def __init__(self, db_path="data/events.duckdb"):
        super().__init__()
        self.db = SigmaDuckDB(db_path)
        self.graph = Neo4jEnricher()
        self.fp_learner = FPLearner()
        self.consensus = AsymmetricConsensus(None, None, None) # Mocked init

    def compose(self) -> ComposeResult:
        yield Header(f"pentagensec v4.0 Sentinel | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        with Grid():
            yield DataTable(id="timeline", cursor_type="row")
            with Vertical():
                yield Static("Kill-Chain / Blast-Radius", classes="title")
                yield Static(id="killchain", expand=True)
                yield Static("Event Details", classes="title")
                yield DataTable(id="details", cursor_type="cell")
        with Horizontal(id="controls"):
            yield Label("Hotkeys: [Q]uit [R]efresh [F]alse-Positive [Enter]Drill-down")
            yield Log(id="audit", max_lines=3)
        yield Footer()

    def on_mount(self) -> None:
        """NIST AU-9: Log de inicio de sesión TUI"""
        self.query_one("#audit", Log).write_line(f"SESSION_START user={self.user_id} ts={datetime.now().isoformat()}")

        # Setup Timeline
        table = self.query_one("#timeline", DataTable)
        table.add_columns("TS", "Host", "Severity", "Rule", "Process", "FP%")
        table.cursor_type = "row"
        table.zebra_stripes = True

        # Setup Details
        dt = self.query_one("#details", DataTable)
        dt.add_columns("Field", "Value")

        self.run_worker(self.refresh_data, thread=True)

    async def refresh_data(self) -> None:
        """v4.0: Carga findings de DuckDB. Llamado por [R] o cada 10s"""
        self.query_one("#audit", Log).write_line("Refreshing timeline...")

        # Query: últimos 500 hits con metadata
        hits = self.db.get_recent_hits(limit=500) # Debes implementar en SigmaDuckDB

        table = self.query_one("#timeline", DataTable)
        table.clear()

        for hit in hits:
            fp_prob = self.fp_learner.predict_fp_prob(hit) * 100
            severity_color = {
                "critical": "red", "high": "yellow", "medium": "cyan", "low": "green"
            }.get(hit['severity'], "white")

            table.add_row(
                hit['ts'][:19],
                hit['host'],
                f"[{severity_color}]{hit['severity']}[/]",
                hit['rule_id'],
                hit['image'][:25],
                f"{fp_prob:.0f}%",
                key=hit['event_id']
            )

        self.query_one("#audit", Log).write_line(f"Loaded {len(hits)} findings")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Enter: Drill-down + Blast-radius"""
        self.selected_event_id = event.row_key.value
        self.run_worker(self.drill_down_worker, thread=True)

    async def drill_down_worker(self) -> None:
        """v3.2: Neo4j blast-radius + v3.0: Event details"""
        if not self.selected_event_id:
            return

        event = self.db.get_event_by_id(self.selected_event_id) # Implementar
        if not event:
            return

        # 1. Panel Details
        dt = self.query_one("#details", DataTable)
        dt.clear()
        for k, v in event.items():
            if k in ['cmdline', 'image', 'rule_id', 'host', 'user', 'process_guid', 'parent_process_guid']:
                dt.add_row(k, str(v)[:80])

        # 2. Panel Kill-Chain con Neo4j
        kc = self.query_one("#killchain", Static)
        if event.get('process_guid'):
            radius = self.graph.blast_radius(event['process_guid'], depth=3)
            nodes = radius.get('nodes', [])

            tree = f"Blast-Radius: {len(nodes)} nodos\n\n"
            tree += f"└─ {event['image']} [ORIGIN]\n"
            for i, n in enumerate(nodes[:8]): # Top 8
                prefix = " ├─" if i < len(nodes)-1 else " └─"
                tree += f"{prefix} {n.get('image', 'unknown')} ({n.get('user', '')})\n"
            if len(nodes) > 8:
                tree += f" └─... +{len(nodes)-8} more\n"

            kc.update(tree)
        else:
            kc.update("No process_guid: sin graph enrichment")

        # 3. AU-9 Audit
        self.query_one("#audit", Log).write_line(
            f"DRILL_DOWN event_id={self.selected_event_id} analyst={self.user_id}"
        )

    def action_mark_false_positive(self) -> None:
        """[F]: v3.3 Active Learning feedback"""
        if not self.selected_event_id:
            self.bell()
            return

        event = self.db.get_event_by_id(self.selected_event_id)
        if event:
            self.fp_learner.feedback(event, is_false_positive=True)
            self.query_one("#audit", Log).write_line(
                f"FP_FEEDBACK event_id={self.selected_event_id} rule={event['rule_id']}"
            )
            self.notify(f"Marked as FP. Model retrained.", severity="warning")
            self.run_worker(self.refresh_data, thread=True) # Refresh para ver nuevo FP%

    def action_refresh(self) -> None:
        self.run_worker(self.refresh_data, thread=True)

    @property
    def user_id(self) -> str:
        import getpass
        return getpass.getuser()

if __name__ == "__main__":
    app = SentinelTUI()
    app.run()
