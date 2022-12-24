class MessageParseException(Exception):
    def __init__(self, message, message_type):
        super().__init__(f"Processing message of type {message_type}: {message}")

class ParameterCountException(MessageParseException):
    def __init__(self, parameters, required_count, message_type):
        super().__init__(f"Invalid parameter count {len(parameters)}. {required_count} required.", message_type)

class ParameterImpossibleTypeCastException(MessageParseException):
    def __init__(self, parameter, required_type, message_type):
        super().__init__(f"Cannot interpret message parameter {parameter} ({type(parameter).__name__}) as type {required_type.__name__}", message_type)

class ParameterWrongTypeException(MessageParseException):
    def __init__(self, parameter, required_type, message_type):
        super().__init__(f"Invalid value for parameter of type {required_type.__name__}: {parameter}", message_type)

class MalformedMessageException(MessageParseException):
    def __init__(self, message: bytes):
        super().__init__("Message is not of a valid parseable format: " + str(message), "UNKNOWN")
