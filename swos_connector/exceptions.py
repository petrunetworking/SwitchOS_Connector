# Custom Exceptions
class MikrotikErrorPromptDetect(Exception):
    def __init__(self, error_message):
        super().__init__(error_message)
        self.error_message = error_message

    def __str__(self):
        return f"{self.error_message}"

class MikrotikErrorLoginRejected(Exception):
    def __init__(self, error_message):
        super().__init__(error_message)
        self.error_message = error_message

    def __str__(self):
        return f"{self.error_message}"
class MikrotikConnectionError(Exception):
    def __init__(self, error_message):
        super().__init__(error_message)
        self.error_message = error_message

    def __str__(self):
        return f"{self.error_message}"
class MikrotikValueError(Exception):
    def __init__(self, error_message):
        super().__init__(error_message)
        self.error_message = error_message

    def __str__(self):
        return f"{self.error_message}"