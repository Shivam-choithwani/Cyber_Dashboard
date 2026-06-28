# windows.py
from collections import deque

class SlidingWindowManager:
    def __init__(self, max_size: int = 10):
        self.max_size = max_size
        # Dictionary of deques: key (IP or user) -> deque of events
        self.windows = {}

    def add_event(self, key: str, event: dict) -> list[dict]:
        """Adds an event to the entity's window and returns the complete window."""
        if key not in self.windows:
            self.windows[key] = deque(maxlen=self.max_size)
            
        self.windows[key].append(event)
        return list(self.windows[key])

    def get_window(self, key: str) -> list[dict]:
        """Gets the current list of events for the entity."""
        if key not in self.windows:
            return []
        return list(self.windows[key])
