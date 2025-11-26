import struct

class Smb2NtlmNegotiate:
    def __init__(self, workstation=b'', workstation_extra_len = 0):
        self.signature = b"NTLMSSP\x00"
        self.message_type = b"\x01\x00\x00\x00"
        self.negotiate_flags = b"\x32\x90\x88\xe2"
        self.domain_name_len = b"\x00\x00"
        self.domain_name_max_len = struct.pack('<H', len( workstation ) + workstation_extra_len)
        self.domain_name_buffer_offset = b"\x28\x00\x00\x00"
        self.workstation_len = b"\x00\x00"
        self.workstation_max_len = b"\x00\x00"
        self.workstation_buffer_offset = b"\x28\x00\x00\x00"
        self.version = b"\x06\x01\xb1\x1d\x00\x00\x00\x0f"
        self.payload_domain_name = b""
        self.payload_workstation = workstation

    def get_packet(self):
        return (self.signature +
            self.message_type +
            self.negotiate_flags +
            self.domain_name_len +
            self.domain_name_max_len +
            self.domain_name_buffer_offset +
            self.workstation_len +
            self.workstation_max_len +
            self.workstation_buffer_offset +
            self.version +
            self.payload_domain_name +
            self.payload_workstation)

class Smb2NtlmAuthenticate:
    def __init__(self, timestamp, computer_name=b'', no_nt_challenge_trailing_reserved=False, padding=b''):
        self.signature = b"NTLMSSP\x00"
        self.message_type = b"\x03\x00\x00\x00"
        self.lm_challenge_response_len = b"\x00"*2
        self.lm_challenge_response_max_len = b"\x00"*2
        self.lm_challenge_response_buffer_offset = b"\x00"*4
        self.nt_challenge_response_len = b"\x00"*2  # will calculate later
        self.nt_challenge_response_max_len = b"\x00"*2  # will calculate later
        self.nt_challenge_response_buffer_offset = struct.pack('<I', 0x58 + len(padding))
        self.domain_name_len = b"\x00"*2
        self.domain_name_max_len = b"\x00"*2
        self.domain_name_buffer_offset = b"\x00"*4
        self.user_name_len = b"\x00"*2
        self.user_name_max_len = b"\x00"*2
        self.user_name_buffer_offset = b"\x00"*4
        self.workstation_len = b"\x00"*2
        self.workstation_max_len = b"\x00"*2
        self.workstation_buffer_offset = b"\x00"*4
        self.encrypted_random_session_key_len = b"\x01\x00"
        self.encrypted_random_session_key_max_len = b"\x01\x00"
        self.encrypted_random_session_key_buffer_offset = b"\x00"*4  # don't care where
        self.negotiate_flags = b"\x36\x82\x8a\xe2"
        self.version = b"\x00"*8
        self.mic = b"\x00"*16
        self.timestamp = timestamp
        self.computer_name = computer_name
        self.no_nt_challenge_trailing_reserved = no_nt_challenge_trailing_reserved
        self.padding = padding

    def nt_challenge_response(self):
        nt_proof_str = b"\x00"*16
        resp_type = b"\x01"
        hi_resp_type = b"\x01"
        reserved1 = b"\x00"*2
        reserved2 = b"\x00"*4
        timestamp_but_not_the_important_one = b"\x00"*8
        client_challenge = b"\x00"*8
        reserved3 = b"\x00"*4
        ntlmv2_client_challenge_timestamp = b"\x07\x00\x08\x00" + self.timestamp
        ntlmv2_client_challenge_domain_name = b"\x02\x00\x00\x00"
        ntlmv2_client_challenge_computer_name = b"\x01\x00" + struct.pack('<H', len(self.computer_name)) + self.computer_name
        ntlmv2_client_challenge_last = b"\x00"*4
        reserved4 = b"\x00"*4 if not self.no_nt_challenge_trailing_reserved else b""
        return (nt_proof_str +
            resp_type +
            hi_resp_type +
            reserved1 +
            reserved2 +
            timestamp_but_not_the_important_one +
            client_challenge +
            reserved3 +
            ntlmv2_client_challenge_timestamp +
            ntlmv2_client_challenge_domain_name +
            ntlmv2_client_challenge_computer_name +
            ntlmv2_client_challenge_last +
            reserved4)

    def get_packet(self):
        nt_challenge_response = self.nt_challenge_response()
        self.nt_challenge_response_len = struct.pack('<H', len(nt_challenge_response))
        self.nt_challenge_response_max_len = struct.pack('<H', len(nt_challenge_response))
        return (self.signature +
            self.message_type +
            self.lm_challenge_response_len +
            self.lm_challenge_response_max_len +
            self.lm_challenge_response_buffer_offset +
            self.nt_challenge_response_len +
            self.nt_challenge_response_max_len +
            self.nt_challenge_response_buffer_offset +
            self.domain_name_len +
            self.domain_name_max_len +
            self.domain_name_buffer_offset +
            self.user_name_len +
            self.user_name_max_len +
            self.user_name_buffer_offset +
            self.workstation_len +
            self.workstation_max_len +
            self.workstation_buffer_offset +
            self.encrypted_random_session_key_len +
            self.encrypted_random_session_key_max_len +
            self.encrypted_random_session_key_buffer_offset +
            self.negotiate_flags +
            self.version +
            self.mic +
            self.padding +
            nt_challenge_response)
