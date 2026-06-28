# embeddings.py

class RouteEmbeddingMapping:
    def __init__(self):
        # Seed map with common known endpoints to guarantee stable indexing
        self.path_map = {
            "/": 0,
            "/auth/login": 1,
            "/auth/register": 2,
            "/products/": 3,
            "/categories/": 4,
            "/cart/": 5,
            "/orders/": 6,
            "/reviews/": 7,
            "/users/me": 8,
        }
        self.counter = len(self.path_map)

    def get_index(self, path: str) -> int:
        """Translates a path string to a numeric index identifier."""
        if not path:
            return 0
            
        # Clean path variables (e.g. /products/12 -> /products/:id)
        cleaned = path.rstrip('/')
        parts = cleaned.split('/')
        
        # Simple heuristic to normalize IDs in paths
        for idx, part in enumerate(parts):
            if part.isdigit() or len(part) > 20: # matches numerical IDs and UUIDs
                parts[idx] = ":id"
        cleaned = "/".join(parts) or "/"
        
        if cleaned not in self.path_map:
            self.path_map[cleaned] = self.counter
            self.counter += 1
            
        return self.path_map[cleaned]
