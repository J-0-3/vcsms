import re
from .exceptions.message_parser import ParameterCountException, ParameterImpossibleTypeCastException, ParameterWrongTypeException, MalformedMessageException


class MessageParser:
    def __init__(self, incoming_message_types: dict, outgoing_message_types: dict, response_map: dict):
        self.incoming = incoming_message_types
        self.outgoing = outgoing_message_types    
        self.response_map = response_map

    def interpret_message_values(self, values: list, message_type: str) -> list:
        #  cast an array of byte strings to the values specified in the message schema
        if message_type in self.incoming:
            message_schema = self.incoming[message_type]
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
            except TypeError:
                raise ParameterImpossibleTypeCastException(v, types[i], message_type)
        return casted

    def construct_message(self,recipient: str, message_type: str, *values) -> bytes:
        if message_type in self.outgoing:
            message_schema = self.outgoing[message_type]
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
        message += message_type.encode() + b':'     # message must end with : for 0 argument types
        for v in values_as_bytes[:-1]:
            message += v + b':'
        if len(values_as_bytes) > 0:
            message += values_as_bytes[-1]
        return message

    def parse_message(self, data: bytes) -> tuple[str, str, list]:
        if re.fullmatch(b'^[0-9a-fA-F]+:[A-z]+(:[A-z0-9]+)*(:[A-z0-9]*)$', data) is None:
            raise MalformedMessageException(data)
        sender, message_type, payload = data.split(b':', 2)
        sender = sender.decode('utf-8')
        message_type = message_type.decode('utf-8')

        if payload:
            message_values = self.interpret_message_values(payload.split(b':'), message_type)
        else:
            message_values = []
        return sender, message_type, message_values

    def handle(self, sender: str, message_type: str, values: list) -> bytes:
        """Handle the message using the handler function given in the response map and return the response.

        Args:
            sender (str): The message sender
            message_type (str): The message type
            values (list): The message values

        Returns:
            bytes: _description_
        """
        if message_type in self.response_map:                
            response = self.response_map[message_type](sender, values)
            if response:
                return self.construct_message(sender, response[0], *(response[1]))
        return b''
