# from Crypto.Cipher import AES, PKCS1_OAEP
# from Crypto.PublicKey import RSA
# from Crypto.Random import get_random_bytes
# from Crypto.Util.Padding import pad, unpad
# from nacl.secret import SecretBox
# from nacl.public import PrivateKey, PublicKey, Box
# from nacl.utils import random
# from steganography.steganography import Steganography
# import os
# import wave
# import json
# from PIL import Image
# import io
# import mimetypes

# class CryptoUtils:
#     def __init__(self):
#         self.AES_KEY_SIZE = 32  # 256 bits
#         self.NONCE_SIZE = 24    # for PyNaCl
#         self.CHUNK_SIZE = 64 * 1024  # 64KB chunks for large files
        
#     def get_file_type(self, filepath):
#         """
#         Determine file type and return appropriate handler
#         """
#         mime_type, _ = mimetypes.guess_type(filepath)
#         if not mime_type:
#             return 'binary'
        
#         if mime_type.startswith('image'):
#             return 'image'
#         elif mime_type.startswith('audio'):
#             return 'audio'
#         elif mime_type.startswith('video'):
#             return 'video'
#         elif mime_type.startswith('text'):
#             return 'text'
#         else:
#             return 'binary'

#     # AES Methods
#     def aes_encrypt_file(self, input_file, output_file, key=None):
#         """
#         Encrypt any file using AES-256-CBC with streaming for large files
#         """
#         if key is None:
#             key = get_random_bytes(self.AES_KEY_SIZE)

#         try:
#             cipher = AES.new(key, AES.MODE_CBC)
#             file_type = self.get_file_type(input_file)
            
#             with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
#                 # Write file type and IV
#                 outfile.write(file_type.encode().ljust(16))
#                 outfile.write(cipher.iv)
                
#                 # Process file in chunks
#                 while True:
#                     chunk = infile.read(self.CHUNK_SIZE)
#                     if len(chunk) == 0:
#                         break
#                     elif len(chunk) % 16 != 0:
#                         chunk = pad(chunk, AES.block_size)
#                     outfile.write(cipher.encrypt(chunk))
            
#             return key
            
#         except Exception as e:
#             raise Exception(f"AES encryption failed: {str(e)}")

#     def aes_decrypt_file(self, input_file, output_file, key):
#         """
#         Decrypt AES encrypted file with streaming support
#         """
#         try:
#             with open(input_file, 'rb') as infile:
#                 # Read file type and IV
#                 file_type = infile.read(16).strip().decode()
#                 iv = infile.read(16)
#                 cipher = AES.new(key, AES.MODE_CBC, iv)
                
#                 with open(output_file, 'wb') as outfile:
#                     while True:
#                         chunk = infile.read(self.CHUNK_SIZE)
#                         if len(chunk) == 0:
#                             break
#                         decrypted_chunk = cipher.decrypt(chunk)
#                         if len(chunk) < self.CHUNK_SIZE:
#                             decrypted_chunk = unpad(decrypted_chunk, AES.block_size)
#                         outfile.write(decrypted_chunk)
                        
#         except Exception as e:
#             raise Exception(f"AES decryption failed: {str(e)}")

#     # PyNaCl Methods for All File Types
#     def nacl_encrypt_file(self, input_file, output_file, recipient_public_key=None):
#         """
#         Encrypt any file using PyNaCl with streaming support
#         """
#         try:
#             file_type = self.get_file_type(input_file)
            
#             if recipient_public_key is None:
#                 # Symmetric encryption
#                 key = random(SecretBox.KEY_SIZE)
#                 box = SecretBox(key)
#             else:
#                 # Asymmetric encryption
#                 sender_private = PrivateKey.generate()
#                 recipient_public = PublicKey(recipient_public_key)
#                 box = Box(sender_private, recipient_public)
#                 key = sender_private.encode()

#             with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
#                 # Write file type
#                 outfile.write(file_type.encode().ljust(16))
                
#                 # Process file in chunks
#                 while True:
#                     chunk = infile.read(self.CHUNK_SIZE)
#                     if not chunk:
#                         break
#                     encrypted_chunk = box.encrypt(chunk)
#                     chunk_size = len(encrypted_chunk).to_bytes(8, 'big')
#                     outfile.write(chunk_size)
#                     outfile.write(encrypted_chunk)
                    
#             return key
            
#         except Exception as e:
#             raise Exception(f"PyNaCl encryption failed: {str(e)}")

#     def nacl_decrypt_file(self, input_file, output_file, key, sender_public_key=None):
#         """
#         Decrypt PyNaCl encrypted file with streaming support
#         """
#         try:
#             with open(input_file, 'rb') as infile:
#                 # Read file type
#                 file_type = infile.read(16).strip().decode()
                
#                 if sender_public_key is None:
#                     # Symmetric decryption
#                     box = SecretBox(key)
#                 else:
#                     # Asymmetric decryption
#                     recipient_private = PrivateKey(key)
#                     sender_public = PublicKey(sender_public_key)
#                     box = Box(recipient_private, sender_public)

#                 with open(output_file, 'wb') as outfile:
#                     while True:
#                         chunk_size_bytes = infile.read(8)
#                         if not chunk_size_bytes:
#                             break
#                         chunk_size = int.from_bytes(chunk_size_bytes, 'big')
#                         encrypted_chunk = infile.read(chunk_size)
#                         decrypted_chunk = box.decrypt(encrypted_chunk)
#                         outfile.write(decrypted_chunk)
                        
#         except Exception as e:
#             raise Exception(f"PyNaCl decryption failed: {str(e)}")

#     # Enhanced Steganography Methods
#     def hide_file_in_image(self, input_image, input_file, output_image):
#         """
#         Hide any file type within an image using steganography
#         """
#         try:
#             # Read the file to hide
#             with open(input_file, 'rb') as f:
#                 file_data = f.read()
#                 file_type = self.get_file_type(input_file)
            
#             # Prepare metadata
#             metadata = {
#                 'file_type': file_type,
#                 'file_size': len(file_data)
#             }
#             metadata_str = json.dumps(metadata)
            
#             # Combine metadata and file data
#             full_data = f"{metadata_str}|||||{file_data.hex()}"
            
#             # Hide data in image
#             Steganography.encode(input_image, output_image, full_data)
            
#         except Exception as e:
#             raise Exception(f"Steganography encoding failed: {str(e)}")

#     def extract_file_from_image(self, stego_image, output_file):
#         """
#         Extract hidden file from steganographic image
#         """
#         try:
#             # Extract hidden data
#             extracted_data = Steganography.decode(stego_image)
            
#             # Split metadata and file data
#             metadata_str, hex_data = extracted_data.split('|||||')
#             metadata = json.loads(metadata_str)
            
#             # Convert hex back to bytes and save
#             file_data = bytes.fromhex(hex_data)
#             with open(output_file, 'wb') as f:
#                 f.write(file_data)
                
#             return metadata['file_type']
            
#         except Exception as e:
#             raise Exception(f"Steganography decoding failed: {str(e)}")

#     # RSA Methods for All File Types
#     def rsa_encrypt_file(self, input_file, output_file, public_key):
#         """
#         Encrypt file using RSA with hybrid encryption (RSA + AES)
#         """
#         try:
#             # Generate AES key for actual file encryption
#             aes_key = get_random_bytes(self.AES_KEY_SIZE)
            
#             # Encrypt AES key with RSA
#             rsa_key = RSA.import_key(public_key)
#             cipher_rsa = PKCS1_OAEP.new(rsa_key)
#             encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            
#             # Encrypt file with AES
#             cipher_aes = AES.new(aes_key, AES.MODE_CBC)
#             file_type = self.get_file_type(input_file)
            
#             with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
#                 # Write encrypted AES key length and key
#                 outfile.write(len(encrypted_aes_key).to_bytes(4, 'big'))
#                 outfile.write(encrypted_aes_key)
                
#                 # Write file type and IV
#                 outfile.write(file_type.encode().ljust(16))
#                 outfile.write(cipher_aes.iv)
                
#                 # Encrypt file content
#                 while True:
#                     chunk = infile.read(self.CHUNK_SIZE)
#                     if len(chunk) == 0:
#                         break
#                     elif len(chunk) % 16 != 0:
#                         chunk = pad(chunk, AES.block_size)
#                     outfile.write(cipher_aes.encrypt(chunk))
                    
#         except Exception as e:
#             raise Exception(f"RSA encryption failed: {str(e)}")

#     def rsa_decrypt_file(self, input_file, output_file, private_key):
#         """
#         Decrypt RSA encrypted file (hybrid decryption)
#         """
#         try:
#             with open(input_file, 'rb') as infile:
#                 # Read and decrypt AES key
#                 key_length = int.from_bytes(infile.read(4), 'big')
#                 encrypted_aes_key = infile.read(key_length)
                
#                 rsa_key = RSA.import_key(private_key)
#                 cipher_rsa = PKCS1_OAEP.new(rsa_key)
#                 aes_key = cipher_rsa.decrypt(encrypted_aes_key)
                
#                 # Read file type and IV
#                 file_type = infile.read(16).strip().decode()
#                 iv = infile.read(16)
#                 cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
                
#                 # Decrypt file content
#                 with open(output_file, 'wb') as outfile:
#                     while True:
#                         chunk = infile.read(self.CHUNK_SIZE)
#                         if len(chunk) == 0:
#                             break
#                         decrypted_chunk = cipher_aes.decrypt(chunk)
#                         if len(chunk) < self.CHUNK_SIZE:
#                             decrypted_chunk = unpad(decrypted_chunk, AES.block_size)
#                         outfile.write(decrypted_chunk)
                        
#         except Exception as e:
#             raise Exception(f"RSA decryption failed: {str(e)}")

#     # Special handlers for audio/video files
#     def encrypt_media_file(self, input_file, output_file, method='aes', key=None, public_key=None):
#         """
#         Encrypt audio/video files with metadata preservation
#         """
#         file_type = self.get_file_type(input_file)
        
#         if file_type not in ['audio', 'video']:
#             raise ValueError("This method is only for audio/video files")
            
#         if method == 'aes':
#             return self.aes_encrypt_file(input_file, output_file, key)
#         elif method == 'nacl':
#             return self.nacl_encrypt_file(input_file, output_file, public_key)
#         elif method == 'rsa':
#             return self.rsa_encrypt_file(input_file, output_file, public_key)
#         else:
#             raise ValueError("Unsupported encryption method")

#     def decrypt_media_file(self, input_file, output_file, method='aes', key=None, private_key=None):
#         """
#         Decrypt audio/video files with metadata restoration
#         """
#         if method == 'aes':
#             return self.aes_decrypt_file(input_file, output_file, key)
#         elif method == 'nacl':
#             return self.nacl_decrypt_file(input_file, output_file, key)
#         elif method == 'rsa':
#             return self.rsa_decrypt_file(input_file, output_file, private_key)
#         else:
#             raise ValueError("Unsupported decryption method")

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from nacl.secret import SecretBox
from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import random
from steganography.steganography import Steganography
import os
import wave
import json
from PIL import Image
import io
import mimetypes
from key import get_key

class CryptoUtils:
    def __init__(self):
        self.AES_KEY_SIZE = 32  # 256 bits
        self.NONCE_SIZE = 24    # for PyNaCl
        self.CHUNK_SIZE = 64 * 1024  # 64KB chunks for large files
        
    def get_file_type(self, filepath):
        """
        Determine file type and return appropriate handler
        """
        mime_type, _ = mimetypes.guess_type(filepath)
        if not mime_type:
            return 'binary'
        
        if mime_type.startswith('image'):
            return 'image'
        elif mime_type.startswith('audio'):
            return 'audio'
        elif mime_type.startswith('video'):
            return 'video'
        elif mime_type.startswith('text'):
            return 'text'
        else:
            return 'binary'

    def aes_encrypt_file(self, input_file, output_file, key=None):
        """
        Encrypt any file using AES-256-CBC with streaming for large files
        """
        if key is None:
            key = get_key("encryption")

        try:
            cipher = AES.new(key, AES.MODE_CBC)
            file_type = self.get_file_type(input_file)
            
            with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
                # Write file type and IV
                outfile.write(file_type.encode().ljust(16))
                outfile.write(cipher.iv)
                
                # Process file in chunks
                while True:
                    chunk = infile.read(self.CHUNK_SIZE)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk = pad(chunk, AES.block_size)
                    outfile.write(cipher.encrypt(chunk))
            
            return key
            
        except Exception as e:
            raise Exception(f"AES encryption failed: {str(e)}")

    def aes_decrypt_file(self, input_file, output_file, key=None):
        """
        Decrypt AES encrypted file with streaming support
        """
        if key is None:
            key = get_key("decryption")

        try:
            with open(input_file, 'rb') as infile:
                # Read file type and IV
                file_type = infile.read(16).strip().decode()
                iv = infile.read(16)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                
                with open(output_file, 'wb') as outfile:
                    while True:
                        chunk = infile.read(self.CHUNK_SIZE)
                        if len(chunk) == 0:
                            break
                        decrypted_chunk = cipher.decrypt(chunk)
                        if len(chunk) < self.CHUNK_SIZE:
                            decrypted_chunk = unpad(decrypted_chunk, AES.block_size)
                        outfile.write(decrypted_chunk)
                        
        except Exception as e:
            raise Exception(f"AES decryption failed: {str(e)}")

    def nacl_encrypt_file(self, input_file, output_file, recipient_public_key=None):
        """
        Encrypt any file using PyNaCl with streaming support
        """
        try:
            file_type = self.get_file_type(input_file)
            
            if recipient_public_key is None:
                # Symmetric encryption
                key = get_key("encryption")
                box = SecretBox(key)
            else:
                # Asymmetric encryption
                sender_private = PrivateKey.generate()
                recipient_public = PublicKey(recipient_public_key)
                box = Box(sender_private, recipient_public)
                key = sender_private.encode()

            with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
                # Write file type
                outfile.write(file_type.encode().ljust(16))
                
                # Process file in chunks
                while True:
                    chunk = infile.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    encrypted_chunk = box.encrypt(chunk)
                    chunk_size = len(encrypted_chunk).to_bytes(8, 'big')
                    outfile.write(chunk_size)
                    outfile.write(encrypted_chunk)
                    
            return key
            
        except Exception as e:
            raise Exception(f"PyNaCl encryption failed: {str(e)}")

    def nacl_decrypt_file(self, input_file, output_file, key=None, sender_public_key=None):
        """
        Decrypt PyNaCl encrypted file with streaming support
        """
        if key is None:
            key = get_key("decryption")

        try:
            with open(input_file, 'rb') as infile:
                # Read file type
                file_type = infile.read(16).strip().decode()
                
                if sender_public_key is None:
                    # Symmetric decryption
                    box = SecretBox(key)
                else:
                    # Asymmetric decryption
                    recipient_private = PrivateKey(key)
                    sender_public = PublicKey(sender_public_key)
                    box = Box(recipient_private, sender_public)

                with open(output_file, 'wb') as outfile:
                    while True:
                        chunk_size_bytes = infile.read(8)
                        if not chunk_size_bytes:
                            break
                        chunk_size = int.from_bytes(chunk_size_bytes, 'big')
                        encrypted_chunk = infile.read(chunk_size)
                        decrypted_chunk = box.decrypt(encrypted_chunk)
                        outfile.write(decrypted_chunk)
                        
        except Exception as e:
            raise Exception(f"PyNaCl decryption failed: {str(e)}")

    def hide_file_in_image(self, input_image, input_file, output_image):
        """
        Hide any file type within an image using steganography
        """
        try:
            # Read the file to hide
            with open(input_file, 'rb') as f:
                file_data = f.read()
                file_type = self.get_file_type(input_file)
            
            # Prepare metadata
            metadata = {
                'file_type': file_type,
                'file_size': len(file_data)
            }
            metadata_str = json.dumps(metadata)
            
            # Combine metadata and file data
            full_data = f"{metadata_str}|||||{file_data.hex()}"
            
            # Hide data in image
            Steganography.encode(input_image, output_image, full_data)
            
        except Exception as e:
            raise Exception(f"Steganography encoding failed: {str(e)}")

    def extract_file_from_image(self, stego_image, output_file):
        """
        Extract hidden file from steganographic image
        """
        try:
            # Extract hidden data
            extracted_data = Steganography.decode(stego_image)
            
            # Split metadata and file data
            metadata_str, hex_data = extracted_data.split('|||||')
            metadata = json.loads(metadata_str)
            
            # Convert hex back to bytes and save
            file_data = bytes.fromhex(hex_data)
            with open(output_file, 'wb') as f:
                f.write(file_data)
                
            return metadata['file_type']
            
        except Exception as e:
            raise Exception(f"Steganography decoding failed: {str(e)}")

    def rsa_encrypt_file(self, input_file, output_file, public_key):
        """
        Encrypt file using RSA with hybrid encryption (RSA + AES)
        """
        try:
            # Get AES key for actual file encryption
            aes_key = get_key("encryption")
            
            # Encrypt AES key with RSA
            rsa_key = RSA.import_key(public_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            
            # Encrypt file with AES
            cipher_aes = AES.new(aes_key, AES.MODE_CBC)
            file_type = self.get_file_type(input_file)
            
            with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
                # Write encrypted AES key length and key
                outfile.write(len(encrypted_aes_key).to_bytes(4, 'big'))
                outfile.write(encrypted_aes_key)
                
                # Write file type and IV
                outfile.write(file_type.encode().ljust(16))
                outfile.write(cipher_aes.iv)
                
                # Encrypt file content
                while True:
                    chunk = infile.read(self.CHUNK_SIZE)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk = pad(chunk, AES.block_size)
                    outfile.write(cipher_aes.encrypt(chunk))
                    
        except Exception as e:
            raise Exception(f"RSA encryption failed: {str(e)}")

    def rsa_decrypt_file(self, input_file, output_file, private_key):
        """
        Decrypt RSA encrypted file (hybrid decryption)
        """
        try:
            with open(input_file, 'rb') as infile:
                # Read and decrypt AES key
                key_length = int.from_bytes(infile.read(4), 'big')
                encrypted_aes_key = infile.read(key_length)
                
                rsa_key = RSA.import_key(private_key)
                cipher_rsa = PKCS1_OAEP.new(rsa_key)
                aes_key = cipher_rsa.decrypt(encrypted_aes_key)
                
                # Read file type and IV
                file_type = infile.read(16).strip().decode()
                iv = infile.read(16)
                cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
                
                # Decrypt file content
                with open(output_file, 'wb') as outfile:
                    while True:
                        chunk = infile.read(self.CHUNK_SIZE)
                        if len(chunk) == 0:
                            break
                        decrypted_chunk = cipher_aes.decrypt(chunk)
                        if len(chunk) < self.CHUNK_SIZE:
                            decrypted_chunk = unpad(decrypted_chunk, AES.block_size)
                        outfile.write(decrypted_chunk)
                        
        except Exception as e:
            raise Exception(f"RSA decryption failed: {str(e)}")

    def encrypt_media_file(self, input_file, output_file, method='aes', key=None, public_key=None):
        """
        Encrypt audio/video files with metadata preservation
        """
        file_type = self.get_file_type(input_file)
        
        if file_type not in ['audio', 'video']:
            raise ValueError("This method is only for audio/video files")

        if key is None:
            key = get_key("encryption")
            
        if method == 'aes':
            return self.aes_encrypt_file(input_file, output_file, key)
        elif method == 'nacl':
            return self.nacl_encrypt_file(input_file, output_file, public_key)
        elif method == 'rsa':
            return self.rsa_encrypt_file(input_file, output_file, public_key)
        else:
            raise ValueError("Unsupported encryption method")

    def decrypt_media_file(self, input_file, output_file, method='aes', key=None, private_key=None):
        """
        Decrypt audio/video files with metadata restoration
        """
        if key is None:
            key = get_key("decryption")

        if method == 'aes':
            return self.aes_decrypt_file(input_file, output_file, key)
        elif method == 'nacl':
            return self.nacl_decrypt_file(input_file, output_file, key)
        elif method == 'rsa':
            return self.rsa_decrypt_file(input_file, output_file, private_key)
        else:
            raise ValueError("Unsupported decryption method")

    def decrypt_media(self, input_file, output_file, key=None):
        """
        Decrypt an AES encrypted media file using chunked streaming.
        """
        if key is None:
            key = get_key("decryption")

        try:
            with open(input_file, 'rb') as infile:
                # Read file type and IV
                file_type = infile.read(16).strip().decode()
                iv = infile.read(16)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                
                with open(output_file, 'wb') as outfile:
                    while True:
                        chunk = infile.read(self.CHUNK_SIZE)
                        if len(chunk) == 0:
                            break
                        decrypted_chunk = cipher.decrypt(chunk)
                        if len(chunk) < self.CHUNK_SIZE:
                            decrypted_chunk = unpad(decrypted_chunk, AES.block_size)
                        outfile.write(decrypted_chunk)
            
            print(f"Media file {input_file} decrypted successfully to {output_file}")
            
        except Exception as e:
            raise Exception(f"Media decryption failed: {str(e)}")

    def generate_key_pair(self):
        """
        Generate RSA key pair for asymmetric encryption
        """
        try:
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            return private_key, public_key
        except Exception as e:
            raise Exception(f"Key pair generation failed: {str(e)}")

    def verify_file_integrity(self, original_file, decrypted_file):
        """
        Verify the integrity of a decrypted file by comparing with the original
        """
        try:
            with open(original_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
                while True:
                    chunk1 = f1.read(self.CHUNK_SIZE)
                    chunk2 = f2.read(self.CHUNK_SIZE)
                    
                    if chunk1 != chunk2:
                        return False
                    
                    if not chunk1:  # EOF reached
                        break
                        
                return True
                
        except Exception as e:
            raise Exception(f"File integrity verification failed: {str(e)}")

    def get_file_hash(self, filepath, algorithm='sha256'):
        """
        Calculate file hash using specified algorithm
        """
        from hashlib import sha256, sha512, md5
        
        hash_functions = {
            'sha256': sha256,
            'sha512': sha512,
            'md5': md5
        }
        
        if algorithm not in hash_functions:
            raise ValueError(f"Unsupported hash algorithm. Use one of: {', '.join(hash_functions.keys())}")
            
        try:
            hash_obj = hash_functions[algorithm]()
            
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    hash_obj.update(chunk)
                    
            return hash_obj.hexdigest()
            
        except Exception as e:
            raise Exception(f"File hash calculation failed: {str(e)}")

    def secure_delete_file(self, filepath, passes=3):
        """
        Securely delete a file by overwriting it multiple times before deletion
        """
        import random
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File {filepath} not found")
            
        try:
            file_size = os.path.getsize(filepath)
            
            for pass_num in range(passes):
                with open(filepath, 'wb') as f:
                    # Pass 1: zeros
                    if pass_num == 0:
                        f.write(b'\x00' * file_size)
                    # Pass 2: ones
                    elif pass_num == 1:
                        f.write(b'\xFF' * file_size)
                    # Pass 3+: random data
                    else:
                        f.write(os.urandom(file_size))
                        
            os.remove(filepath)
            return True
            
        except Exception as e:
            raise Exception(f"Secure file deletion failed: {str(e)}")

    def encrypt_directory(self, input_dir, output_dir, method='aes', key=None, public_key=None):
        """
        Recursively encrypt all files in a directory
        """
        if not os.path.exists(input_dir):
            raise FileNotFoundError(f"Input directory {input_dir} not found")
            
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        try:
            encrypted_files = []
            
            for root, _, files in os.walk(input_dir):
                for file in files:
                    input_path = os.path.join(root, file)
                    relative_path = os.path.relpath(input_path, input_dir)
                    output_path = os.path.join(output_dir, relative_path + '.encrypted')
                    
                    # Create necessary subdirectories in output path
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)
                    
                    # Encrypt the file using specified method
                    if method == 'aes':
                        self.aes_encrypt_file(input_path, output_path, key)
                    elif method == 'nacl':
                        self.nacl_encrypt_file(input_path, output_path, public_key)
                    elif method == 'rsa':
                        self.rsa_encrypt_file(input_path, output_path, public_key)
                    else:
                        raise ValueError("Unsupported encryption method")
                        
                    encrypted_files.append((relative_path, output_path))
                    
            return encrypted_files
            
        except Exception as e:
            raise Exception(f"Directory encryption failed: {str(e)}")

    def decrypt_directory(self, input_dir, output_dir, method='aes', key=None, private_key=None):
        """
        Recursively decrypt all encrypted files in a directory
        """
        if not os.path.exists(input_dir):
            raise FileNotFoundError(f"Input directory {input_dir} not found")
            
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        try:
            decrypted_files = []
            
            for root, _, files in os.walk(input_dir):
                for file in files:
                    if file.endswith('.encrypted'):
                        input_path = os.path.join(root, file)
                        relative_path = os.path.relpath(input_path, input_dir)
                        output_path = os.path.join(output_dir, 
                                                 relative_path[:-len('.encrypted')])
                        
                        # Create necessary subdirectories in output path
                        os.makedirs(os.path.dirname(output_path), exist_ok=True)
                        
                        # Decrypt the file using specified method
                        if method == 'aes':
                            self.aes_decrypt_file(input_path, output_path, key)
                        elif method == 'nacl':
                            self.nacl_decrypt_file(input_path, output_path, key)
                        elif method == 'rsa':
                            self.rsa_decrypt_file(input_path, output_path, private_key)
                        else:
                            raise ValueError("Unsupported decryption method")
                            
                        decrypted_files.append((relative_path, output_path))
                    
            return decrypted_files
            
        except Exception as e:
            raise Exception(f"Directory decryption failed: {str(e)}")

    def backup_metadata(self, filepath, backup_path=None):
        """
        Backup file metadata before encryption
        """
        try:
            metadata = {
                'filename': os.path.basename(filepath),
                'size': os.path.getsize(filepath),
                'created': os.path.getctime(filepath),
                'modified': os.path.getmtime(filepath),
                'accessed': os.path.getatime(filepath),
                'permissions': oct(os.stat(filepath).st_mode)[-3:],
                'file_type': self.get_file_type(filepath),
                'hash': self.get_file_hash(filepath)
            }
            
            if backup_path:
                with open(backup_path, 'w') as f:
                    json.dump(metadata, f, indent=4)
                    
            return metadata
            
        except Exception as e:
            raise Exception(f"Metadata backup failed: {str(e)}")

    def restore_metadata(self, filepath, metadata):
        """
        Restore file metadata after decryption
        """
        try:
            # Restore timestamps
            os.utime(filepath, (metadata['accessed'], metadata['modified']))
            
            # Restore permissions
            os.chmod(filepath, int(metadata['permissions'], 8))
            
            return True
            
        except Exception as e:
            raise Exception(f"Metadata restoration failed: {str(e)}")