class igider:
    def encrypt(self, data):
        import os
        import base64
        import logging
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidTag
        # Ensure logger is initialized
        if not hasattr(self, 'logger'):
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(logging.INFO)
            if not self.logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)

        if not self.agent_config["enc_key"]["value"] == "none" and len(data) > 0:
            try:
                # Get and validate the master key
                raw_key = base64.b64decode(self.agent_config["enc_key"]["enc_key"])
                if len(raw_key) not in {16, 24, 32}:
                    raise ValueError(f"Invalid key length: {len(raw_key)} bytes; must be 16, 24, or 32 bytes")
                
                # Derive a 32-byte key using HKDF
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,  # ChaCha20-Poly1305 requires 32 bytes
                    salt=None,
                    info=b'igider_encryption',
                    backend=None
                )
                key = hkdf.derive(raw_key)

                # Generate nonce (12 bytes for ChaCha20-Poly1305)
                nonce = os.urandom(12)

                # Initialize cipher
                cipher = ChaCha20Poly1305(key)

                # Encrypt data
                ciphertext = cipher.encrypt(nonce, data, associated_data=None)

                # Log encryption
                self.logger.info("Encrypted data with ChaCha20-Poly1305")

                # Return: nonce + ciphertext (includes 16-byte tag)
                return nonce + ciphertext

            except Exception as e:
                self.logger.error("Encryption failed: %s", str(e))
                raise ValueError(f"Encryption failed: {str(e)}")
        else:
            return data

    def decrypt(self, data):
        import os
        import base64
        import logging
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidTag
        # Ensure logger is initialized
        if not hasattr(self, 'logger'):
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(logging.INFO)
            if not self.logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)

        if not self.agent_config["enc_key"]["value"] == "none":
            if len(data) > 0:
                try:
                    # Get and validate the master key
                    raw_key = base64.b64decode(self.agent_config["enc_key"]["dec_key"])
                    if len(raw_key) not in {16, 24, 32}:
                        raise ValueError(f"Invalid key length: {len(raw_key)} bytes; must be 16, 24, or 32 bytes")
                    
                    # Derive a 32-byte key using HKDF
                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'igider_encryption',
                        backend=None
                    )
                    key = hkdf.derive(raw_key)

                    # Parse components: UUID + nonce + ciphertext
                    uuid = data[:36]
                    nonce = data[36:48]  # 12 bytes for ChaCha20-Poly1305
                    ciphertext = data[48:]  # Includes 16-byte Poly1305 tag

                    # Validate input length
                    if len(ciphertext) < 16:  # At least tag size
                        raise ValueError("Invalid ciphertext length: must include 16-byte tag")

                    # Initialize cipher
                    cipher = ChaCha20Poly1305(key)

                    # Decrypt data
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)

                    # Log decryption
                    self.logger.info("Decrypted data with ChaCha20-Poly1305")

                    # Return UUID + decrypted data as string
                    return (uuid + plaintext).decode('utf-8')

                except InvalidTag:
                    self.logger.error("Decryption failed: Invalid authentication tag")
                    return ""
                except Exception as e:
                    self.logger.error("Decryption failed: %s", str(e))
                    return ""
            else:
                return ""
        else:
            return data.decode('utf-8')