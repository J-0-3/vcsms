import re


class MessageParser:
    def __init__(self, incoming_message_types: dict, outgoing_message_types: dict, response_map: dict = {}):
        self.incoming = incoming_message_types
        self.outgoing = outgoing_message_types    
        self.response_map = response_map

    def interpret_message_values(self, values: list, message_type: str) -> list:
        #  cast an array of byte strings to the values specified in the message schema
        if message_type in self.incoming:
            message_schema = self.incoming[message_type]
        else:
            # print(f"WARNING: Unknown message type {message_type}")
            return values
        length, types, type_info = message_schema
        if len(values) < length:
            print(f"Cannot cast {len(values)} values to {length} types")
            print(values)
            print(message_schema)
            return -1
        casted = []
        for i in range(len(values)):
            try:
                if types[i] is int:
                    casted.append(int(values[i], type_info[i]))
                elif types[i] is str:
                    casted.append(str(values[i], type_info[i]))
                elif types[i] is bytes:
                    casted.append(values[i])
            except TypeError:
                print(f"Cannot cast {values[i]} to {types[i]}")

                return -1
        return casted
        
    def construct_message(self,recipient: str, message_type: str, *values) -> bytes:
        if message_type in self.outgoing:
            message_schema = self.outgoing[message_type]
            length, types, type_info = message_schema
            if len(values) != length:
                print(f"Invalid number of values for message type {message_type}")

            values_as_bytes = []
            for i in range(length):
                if type(values[i]) is not types[i]:
                    print(f"Invalid value for {types[i]}: {values[i]} ({type(values[i])}) while process {message_type}")
                    return b''

                if types[i] is int:
                    if type_info[i] == 10:
                        values_as_bytes.append(str(values[i]).encode('utf-8'))
                    elif type_info[i] == 16:
                        values_as_bytes.append(hex(values[i]).encode('utf-8')[2:])
                elif types[i] is str:
                        values_as_bytes.append(values[i].encode(type_info[i]))
                elif types[i] is bytes:
                        values_as_bytes.append(values[i])
        else:
            # print(f"WARNING: unknown outgoing message type: {message_type}")
            values_as_bytes = values
        message = b''
        message += recipient.encode() + b':'
        message += message_type.encode() + b':'     # message must end with : for 0 argument types
        for v in values_as_bytes[:-1]:
            message += v + b':'
        if len(values_as_bytes) > 0:
            message += values_as_bytes[-1]
        return message

    def parse_message(self, data: bytes) -> tuple:
        try:
            if re.fullmatch(re.compile('^[0-9a-fA-F]+:[A-z]+(:[A-z0-9]+)*(:[A-z0-9]*)$'), data.decode()) is None:
                print("invalid format")
                return ()
            sender, message_type, payload = data.split(b':', 2)
            sender = sender.decode('utf-8')
            message_type = message_type.decode('utf-8')

            if payload:
                message_values = self.interpret_message_values(payload.split(b':'), message_type)
            else:
                message_values = []
            if message_values == -1:
                return ()
            return sender, message_type, message_values
        except Exception as e:
            print(f"Error parsing message data: {e}")
            return ()

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
                else:
                    return b''
        else:
            return b''