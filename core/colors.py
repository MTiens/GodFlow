"""
Color utilities for verbose output formatting.
Provides colored console output for better readability during verbose mode.
"""

import sys
from typing import Optional

class Colors:
    """ANSI color codes for terminal output."""
    
    # Reset
    RESET = '\033[0m'
    
    # Regular colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    
    # Text formatting
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'

class ColorFormatter:
    """Handles colored output for verbose logging."""
    
    def __init__(self, enabled: bool = True):
        """
        Initialize the color formatter.
        
        Args:
            enabled: Whether to enable color output (auto-detects TTY by default)
        """
        self.enabled = enabled and self._supports_color()
    
    def _supports_color(self) -> bool:
        """Check if the terminal supports color output."""
        # Check if output is a terminal and not redirected
        if not hasattr(sys.stdout, 'isatty') or not sys.stdout.isatty():
            return False
        
        # Check for Windows terminal color support
        if sys.platform == "win32":
            try:
                import colorama
                colorama.init()
                return True
            except ImportError:
                # Windows 10 version 1607+ supports ANSI escape sequences
                try:
                    import os
                    return os.name == 'nt' and sys.version_info >= (3, 6)
                except:
                    return False
        
        return True
    
    def format(self, text: str, color: str = '', style: str = '') -> str:
        """
        Format text with color and style.
        
        Args:
            text: Text to format
            color: Color code from Colors class
            style: Style code from Colors class
            
        Returns:
            Formatted text string
        """
        if not self.enabled:
            return text
        
        formatted = f"{style}{color}{text}{Colors.RESET}"
        return formatted
    
    def debug(self, text: str) -> str:
        """Format debug messages in cyan."""
        return self.format(text, Colors.CYAN, Colors.DIM)
    
    def info(self, text: str) -> str:
        """Format info messages in blue."""
        return self.format(text, Colors.BLUE)
    
    def success(self, text: str) -> str:
        """Format success messages in green."""
        return self.format(text, Colors.GREEN, Colors.BOLD)
    
    def warning(self, text: str) -> str:
        """Format warning messages in yellow."""
        return self.format(text, Colors.YELLOW, Colors.BOLD)
    
    def error(self, text: str) -> str:
        """Format error messages in red."""
        return self.format(text, Colors.RED, Colors.BOLD)
    
    def critical(self, text: str) -> str:
        """Format critical messages in red with background."""
        return self.format(text, Colors.BRIGHT_WHITE, Colors.BG_RED + Colors.BOLD)
    
    def highlight(self, text: str) -> str:
        """Format highlighted text in bright white."""
        return self.format(text, Colors.BRIGHT_WHITE, Colors.BOLD)
    
    def baseline(self, text: str) -> str:
        """Format baseline messages in magenta."""
        return self.format(text, Colors.MAGENTA, Colors.BOLD)
    
    def step(self, text: str) -> str:
        """Format step execution messages in bright blue."""
        return self.format(text, Colors.BRIGHT_BLUE)
    
    def payload(self, text: str) -> str:
        """Format payload-related messages in yellow."""
        return self.format(text, Colors.YELLOW)
    
    def vulnerability(self, text: str) -> str:
        """Format vulnerability messages in bright red."""
        return self.format(text, Colors.BRIGHT_RED, Colors.BOLD)
    
    def status_code(self, code: int, text: Optional[str] = None) -> str:
        """Format HTTP status codes with appropriate colors."""
        if text is None:
            text = str(code)
        
        if 200 <= code < 300:
            return self.format(text, Colors.GREEN)
        elif 300 <= code < 400:
            return self.format(text, Colors.YELLOW)
        elif 400 <= code < 500:
            return self.format(text, Colors.RED)
        elif 500 <= code < 600:
            return self.format(text, Colors.BRIGHT_RED, Colors.BOLD)
        else:
            return self.format(text, Colors.WHITE)

# Global color formatter instance
color_formatter = ColorFormatter()

def colored_print(text: str, color_func: Optional[str] = None, **kwargs):
    """
    Print text with color formatting.
    
    Args:
        text: Text to print
        color_func: Color function name (debug, info, success, warning, error, etc.)
        **kwargs: Additional arguments for print()
    """
    if color_func and hasattr(color_formatter, color_func):
        formatter = getattr(color_formatter, color_func)
        text = formatter(text)
    
    print(text, **kwargs)

def format_log_prefix(prefix: str, message: str) -> str:
    """
    Format log messages with colored prefixes.
    
    Args:
        prefix: Log prefix (DEBUG, INFO, ERROR, etc.)
        message: Log message
        
    Returns:
        Formatted log string
    """
    prefix_lower = prefix.lower()
    
    if prefix_lower == 'debug':
        colored_prefix = color_formatter.debug(f"[{prefix}]")
    elif prefix_lower == 'info':
        colored_prefix = color_formatter.info(f"[{prefix}]")
    elif prefix_lower in ['error', 'err']:
        colored_prefix = color_formatter.error(f"[{prefix}]")
    elif prefix_lower in ['warning', 'warn']:
        colored_prefix = color_formatter.warning(f"[{prefix}]")
    elif prefix_lower == 'baseline':
        colored_prefix = color_formatter.baseline(f"[{prefix}]")
    elif prefix_lower == 'success':
        colored_prefix = color_formatter.success(f"[{prefix}]")
    else:
        colored_prefix = color_formatter.highlight(f"[{prefix}]")
    
    return f"{colored_prefix} {message}" 