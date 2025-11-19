from prompt_toolkit.shortcuts import print_formatted_text
from prompt_toolkit.formatted_text import HTML

# Logging helpers for consistent output in the terminal
def log_info(msg): print_formatted_text(HTML(f"<ansiyellow>[ INFO ]</ansiyellow> {msg}"))
def log_error(msg): print_formatted_text(HTML(f"<ansired>[ ERR ]</ansired> {msg}"))
def log_success(msg): print_formatted_text(HTML(f"<ansigreen>[ SUCCESS ]</ansigreen> {msg}"))
def log_warn(msg): print_formatted_text(HTML(f"<ansiyellow>[ WARN ]</ansiyellow> {msg}"))