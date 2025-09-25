class ScanTaskException(Exception):
    """Base exception for scan task related errors"""

    def __init__(self, message, task_id=None, error_code=None):
        self.message = message
        self.task_id = task_id
        self.error_code = error_code
        super().__init__(self.message)

    def __str__(self):
        if self.task_id:
            return f"[Task {self.task_id}] {self.message}"
        return self.message


class NotAdminException(Exception):
    def __init__(self, message, error_code=None):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)

    def __str__(self):
        return self.message
