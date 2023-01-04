class MessageParseException(Exception):
    """Parent class for all custom exceptions thrown by the message parser.
    
    Args: 
        message (str): The exception message to throw
        message_type (str): The type of the message in which the exception occurred (e.g. NewMessage)
    """
    def __init__(self, message, message_type):
        super().__init__(f"Processing message of type {message_type}: {message}")


class ParameterCountException(MessageParseException):
    """The wrong number of parameters were passed in a message for the given message type.

    Args:
        parameters (list): The parameters passed in the message
        required_count (int): The number of parameters required by the message schema
        message_type (str): The message's type as defined in the message schema (e.g. NewMessage)
    """
    def __init__(self, parameters, required_count, message_type):
        super().__init__(f"Invalid parameter count {len(parameters)}. {required_count} required.", message_type)


class ParameterImpossibleTypeCastException(MessageParseException):
    """A parameter given in the message body was unable to be casted to its specified type. 

    Args:
        parameter (bytes): The raw parameter as read from the message body
        required_type (type): The type of the parameter as specified in the message schema
        message_type (str): The message's type as defined in the message schema (e.g. NewMessage)
    """
    def __init__(self, parameter, required_type, message_type):
        super().__init__(f"Cannot interpret message parameter {parameter} as type {required_type.__name__}", message_type)


class ParameterWrongTypeException(MessageParseException):
    """A parameter used in constructing a message did not match the specified type for that parameter in the schema.

    Args:
        parameter (any): The parameter that was passed
        required_type (type): The type of the parameter as specified in the message schema
        message_type(str): The message's type as defined in the message schema (e.g. NewMessage)
    """
    def __init__(self, parameter, required_type, message_type):
        super().__init__(f"Invalid value for parameter of type {required_type.__name__}: {parameter} ({type(parameter).__name__})", message_type)


class MalformedMessageException(MessageParseException):
    """The message was malformed and cannot be parsed by the message parser.

    Args:
        message (bytes): The raw message bytes which were unparseable.
    """
    def __init__(self, message: bytes):
        super().__init__("Message is not of a valid parseable format: " + str(message), "UNKNOWN")

class UnsupportedTypeException(MessageParseException):
    """The type that was attempted to cast to/from is not implemented."""

    def __init__(self, unsupported_type: type):
        super().__init__(f"Type {unsupported_type.__name__} is not supported.")
