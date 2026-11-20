class BaseCheck:
    def __init__(self, connector):
        self.connector = connector

    def run(self):
        """Each subclass must override this method."""
        raise NotImplementedError("Subclasses must implement run()")

    def execute_query(self, query):
        """Execute read-only queries using Umair's core connector."""
        try:
            return self.connector.query(query)
        except Exception as e:
            return {"error": str(e)}