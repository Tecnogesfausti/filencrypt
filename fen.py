import base64
import os
import argparse
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

SALT_FILE = "salt.bin"


def salt_file_for(encrypted_file: str) -> str:
    return f"{encrypted_file}.salt"


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_file(input_file, output_file, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)

    with open(input_file, "rb") as file:
        data = file.read()

    encrypted = f.encrypt(data)

    with open(output_file, "wb") as file:
        file.write(encrypted)

    # Save salt per encrypted file to avoid mismatches between different files.
    with open(salt_file_for(output_file), "wb") as file:
        file.write(salt)

    print(f"✅ Archivo cifrado correctamente → {output_file}")


def decrypt_to_stdout(input_file, password):
    salt_path = salt_file_for(input_file)
    if os.path.exists(salt_path):
        with open(salt_path, "rb") as file:
            salt = file.read()
    else:
        # Backward compatibility with older files that used one shared salt.bin
        with open(SALT_FILE, "rb") as file:
            salt = file.read()

    key = derive_key(password, salt)
    f = Fernet(key)

    with open(input_file, "rb") as file:
        encrypted = file.read()

    decrypted = f.decrypt(encrypted)

    print("\n🔓 Contenido descifrado:\n")
    print(decrypted.decode())


def main():
    parser = argparse.ArgumentParser(description="Cifrar o mostrar archivo descifrado.")
    parser.add_argument("input", help="Archivo de entrada")
    parser.add_argument("output", nargs="?", help="Archivo de salida (solo para cifrar)")

    args = parser.parse_args()

    password = getpass("Introduce la contraseña: ")

    # Si solo hay input → intentar descifrar y mostrar
    if args.output is None:
        try:
            decrypt_to_stdout(args.input, password)
        except Exception:
            print("❌ No se pudo descifrar (contraseña incorrecta o archivo no cifrado).")
        return

    # Si hay input y output → cifrar
    try:
        decrypt_to_stdout(args.input, password)
        print("⚠ El archivo ya parece estar cifrado.")
    except Exception:
        opcion = input("¿Quieres cifrar el archivo? (s/n): ")
        if opcion.lower() == "s":
            encrypt_file(args.input, args.output, password)


if __name__ == "__main__":
    main()
