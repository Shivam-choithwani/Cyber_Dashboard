# windows.py
from collections import deque

class FraudCheckoutWindowManager:
    def __init__(self, max_size: int = 5):
        self.max_size = max_size
        self.windows = {} # user_id -> deque of checkouts

    def add_checkout(self, user_id: str, order_details: dict) -> list[dict]:
        """Appends a checkout transaction to the user's history window."""
        if user_id not in self.windows:
            self.windows[user_id] = deque(maxlen=self.max_size)
            
        self.windows[user_id].append(order_details)
        return list(self.windows[user_id])

    def get_checkout_history(self, user_id: str) -> list[dict]:
        if user_id not in self.windows:
            return []
        return list(self.windows[user_id])
