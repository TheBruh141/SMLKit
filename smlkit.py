import textual.events
from textual import on
from textual.app import App, ComposeResult
from textual.containers import HorizontalScroll, VerticalScroll
from textual.widgets import Footer, Header, Label, Collapsible, Rule, OptionList, Button

from src.pages import Question1


class SMLKit(App):
    """A Textual app to manage stopwatches."""

    BINDINGS = [("d", "toggle_dark", "Toggle dark mode")]

    selector = VerticalScroll(id="main_selector")

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        yield Label("Welcome to SMLKit")
        with VerticalScroll(id="main_content_container"):
            yield Question1()

        yield Footer()

    def on_mount(self):
        """Called when the app is mounted."""
        self.selector.mount()

    def action_toggle_dark(self) -> None:
        """An action to toggle dark mode."""
        self.theme = (
            "textual-dark" if self.theme == "textual-light" else "textual-light"
        )


if __name__ == "__main__":
    app = SMLKit()
    app.run()