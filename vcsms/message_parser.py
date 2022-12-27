"""Defines a message parser class for use by the Client and Server classes."""
import re
from typing import Callable
from .exceptions.message_parser import ParameterCountException, ParameterImpossibleTypeCastException, ParameterWrongTypeException, MalformedMessageException


class MessageParser:
    """A message parser to parse messages and handle them appropriately.
    
    The message parser uses message schemas and a response map to interpret, construct and handle messages.
    
    The message schemas are split into incoming and outgoing messages (as some message types may be valid as responses to a server but not as requests from it.)
    and are always of the form (argument count, [argument types], [type conversion information]). The argument count should define how many arguments are expected,
    the argument types should be python types such as int, str, bytes etc and the type conversion information should be the integer base for integers, string encoding for strings,
    and None for bytes. 
    
    The response map is a dictionary defining functions to execute when each message type is processed. These functions should always take in the client ID
    and message parameters and return a tuple containing the response message type and a tuple of message parameters. They should return None if no response
    is needed.

    Two special response mappings are available which are "unknown" and "default". These define response functions to execute when a message type which is not defined 
    by any message schema or when a message type with no specified response map is processed. They do not need to be implemented but should take an extra parameter second containing
    the message type that was read. 

    Messages always take the form ID:Type: followed by parameters separated by :.
    """
    def __init__(self, incoming_message_types: dict[str, tuple[int, list[type], list]],
                 outgoing_message_types: dict[str, tuple[int, list[type], list]], response_map: dict[str, Callable]):
        """Initialise an instance of the MessageParser class.

        Args:
            incoming_message_types (dict[str, tuple[int, list[type], list]]): A dictionary specifying message types and their corresponding schemas
                (parameter count, parameter types, type conversion information (integer base, string encoding etc)) for incoming messages. 

            outgoing_message_types (dict[str, tuple[int, list[type], list]]): A dictionary specifying message types and their corresponding schemas
                (parameter count, parameter types, type conversion information (integer base, string encoding etc)) for outgoing messages.  

            response_map (dict[str, Callable]): A dictionary specifying message types and their corresponding handler functions which must take two arguments
                of the sender's client ID (str) and the message parameters (tuple) except for the "unknown" and "default" handlers which must also take an extra second argument
                of the message type that was read.
        """
        self._incoming = incoming_message_types
        self._outgoing = outgoing_message_types    
        self._response_map = response_map

    def _interpret_message_values(self, values: list[bytes], message_type: str) -> list[any]:
        """Convert an array of raw bytestrings to the types specified by the message type schema.

        Args:
            values (list[bytes]): The raw values to be converted.
            message_type (str): The name of the message type for which the values are meant. (e.g. NewMessage)

        Raises:
            ParameterCountException: The number of values passed is incorrect according to the message schema. 
            ParameterImpossibleTypeCastException: One of the values passed cannot be converted to the specified type.

        Returns:
            list[any]: The values converted to the types specified by the message schema. 
        """
        if message_type in self._incoming:
            message_schema = self._incoming[message_type]
        else:
            return values

        length, types, type_info = message_schema
        if len(values) < length:
            raise ParameterCountException(values, length, message_type)
        casted = []
        for i,v in enumerate(values):
            try:
                if types[i] is int:
                    casted.append(int(v, type_info[i]))
                elif types[i] is str:
                    casted.append(str(v, type_info[i]))
                elif types[i] is bytes:
                    casted.append(bytes.fromhex(v.decode('utf-8')))
            except TypeError as exception:
                raise ParameterImpossibleTypeCastException(v, types[i], message_type) from exception
        return casted

    def construct_message(self, recipient: str, message_type: str, *values) -> bytes:
        """Construct a message to a specified recipient of a specified type with the specified parameters.

        Args:
            recipient (str): The message's target recipient.
            message_type (str): The message type name (e.g. NewMessage).
            values (Any...): The parameters for the message. 
        Raises:
            ParameterCountException: The wrong number of parameters were supplied for the specified message type. 
            ParameterWrongTypeException: One of the parameters was of a type not specified in the message schema for the given type. 

        Returns:
            bytes: The raw message bytes. 
        """
        if message_type in self._outgoing:
            message_schema = self._outgoing[message_type]
            length, types, type_info = message_schema
            if len(values) != length:
                raise ParameterCountException(values, length, message_type)

            values_as_bytes = []
            for i in range(length):
                if type(values[i]) is not types[i]:
                    raise ParameterWrongTypeException(values[i], types[i], message_type)

                if types[i] is int:
                    if type_info[i] == 10:
                        values_as_bytes.append(str(values[i]).encode('utf-8'))
                    elif type_info[i] == 16:
                        values_as_bytes.append(hex(values[i]).encode('utf-8')[2:])
                elif types[i] is str:
                    values_as_bytes.append(values[i].encode(type_info[i]))
                elif types[i] is bytes:
                    values_as_bytes.append(values[i].hex().encode('utf-8'))
        else:
            values_as_bytes = values
        message = b''
        message += recipient.encode() + b':'
        message += message_type.encode() + b':'
        for v in values_as_bytes[:-1]:
            message += v + b':'
        if len(values_as_bytes) > 0:
            message += values_as_bytes[-1]
        return message

    def parse_message(self, data: bytes) -> tuple[str, str, list]:
        """Parse the raw bytes of a message and extract the sender, message type, and message parameters in the correct types.

        Args:
            data (bytes): The raw message bytes 

        Raises:
            MalformedMessageException: The message is not of a valid format. 
            ParameterCountException: The message did not supply the correct number of parameters.
            ParameterImpossibleTypeCastException: One of the message parameters could not be converted to the correct type.

        Returns:
            tuple[str, str, list]: The sender, message type and parameters in the correct types. 
        """
        if re.fullmatch(b'^[0-9a-fA-F]+:[A-z]+(:[A-z0-9]+)*(:[A-z0-9]*)$', data) is None:
            raise MalformedMessageException(data)
        sender, message_type, payload = data.split(b':', 2)
        sender = sender.decode('utf-8')
        message_type = message_type.decode('utf-8')

        if payload:
            message_values = self._interpret_message_values(payload.split(b':'), message_type)
        else:
            message_values = []
        return sender, message_type, message_values

    def handle(self, sender: str, message_type: str, values: list, override_recipient_field: str = "") -> bytes:
        """Handle the message using the handler function given in the response map and return the response.

        Args:
            sender (str): The message sender
            message_type (str): The message type
            values (list): The message parameters (must be of the types specified in the schema)
            override_recipient_field (str) (optional): Optional value with which to override the
                first "recipient" field of the message. Useful for the server sending messages
                directly where the first field will be interpreted as the sender.
        Returns:
            bytes: The response message as raw bytes.
        """
        if message_type in self._response_map:
            response = self._response_map[message_type](sender, values)
            if response:
                if override_recipient_field:
                    return self.construct_message(override_recipient_field, response[0], *(response[1]))
                return self.construct_message(sender, response[0], *(response[1]))
        elif message_type in self._incoming:
            if "default" in self._response_map:
                response = self._response_map["default"](sender, message_type, values)
                if response:
                    if override_recipient_field:
                        return self.construct_message(override_recipient_field, response[0], *(response[1]))
                    return self.construct_message(sender, response[0], *(response[1]))
        else:
            if "unknown" in self._response_map:
                response = self._response_map["unknown"](sender, message_type, values)
                if response:
                    if override_recipient_field:
                        return self.construct_message(override_recipient_field, response[0], *(response[1]))
                    return self.construct_message(sender, response[0], *(response[1]))
        return b''
