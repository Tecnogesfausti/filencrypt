import base64
import os
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

from algosdk.v2client import algod
from algosdk import mnemonic
from algosdk.transaction import AssetTransferTxn

# ---------- CONFIG ----------

DATOS_FILE = "datos.txt"
SEED_FILE = "seed.txt"
SALT_FILE = "salt.bin"

algod_address = "https://algorand-mainnet-algod.gateway.tatum.io/"
algod_token = ""
algod_client = algod.AlgodClient(algod_token, algod_address)

# ---------- CRYPTO ----------

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

def decrypt_generic(file_name, password):
    salt_path = salt_file_for(file_name)
    if os.path.exists(salt_path):
        with open(salt_path, "rb") as f:
            salt = f.read()
    else:
        # Backward compatibility with old format using shared salt.bin
        with open(SALT_FILE, "rb") as f:
            salt = f.read()

    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(file_name, "rb") as f:
        encrypted = f.read()

    return fernet.decrypt(encrypted)

# ---------- DATA ----------

def cargar_datos(data_bytes):
    lineas = data_bytes.decode().splitlines()
    registros = []

    for linea in lineas:
        partes = linea.split(";")
        if len(partes) == 4:
            try:
                asset_id = int(partes[3].strip())
            except ValueError:
                continue
            registros.append({
                "credito": partes[0].strip(),
                "nombre": partes[1].strip(),
                "direccion": partes[2].strip(),
                "asset_id": asset_id
            })

    return registros

def seleccionar_registros(registros):
    for i, r in enumerate(registros, start=1):
        print(f"{i}. {r['nombre']}")

    entrada = input("Selecciona números (1,2,5): ")

    try:
        indices = list(set(int(x.strip()) for x in entrada.split(",")))
    except:
        print("Entrada inválida")
        return []

    seleccionados = []
    for idx in indices:
        if 1 <= idx <= len(registros):
            seleccionados.append(registros[idx - 1])

    return seleccionados

# ---------- BLOCKCHAIN ----------

def consultar_balances(registros):
    print("\n📊 Consultando balances...\n")
    for r in registros:
        try:
            info = algod_client.account_info(r["direccion"])
            balance_algo = info.get("amount", 0) / 1_000_000
            print(f"{r['nombre']} → {balance_algo} ALGO")
        except Exception as e:
            print(f"Error con {r['nombre']}: {e}")

def enviar_asa(mi_mnemonic, destinos):
    private_key = mnemonic.to_private_key(mi_mnemonic)
    sender = mnemonic.to_public_key(mi_mnemonic)

    params = algod_client.suggested_params()

    for r in destinos:
        try:
            txn = AssetTransferTxn(
                sender=sender,
                sp=params,
                receiver=r["direccion"],
                amt=1,  # puedes cambiar a input si quieres cantidad variable
                index=r["asset_id"]
            )

            signed_txn = txn.sign(private_key)
            txid = algod_client.send_transaction(signed_txn)

            print(f"Enviado ASA {r['asset_id']} a {r['nombre']} → TXID: {txid}")

        except Exception as e:
            print(f"Error enviando a {r['nombre']}: {e}")

# ---------- MAIN LOOP ----------

def obtener_contrasena():
    override = os.getenv("LISTA_PASSWORD")
    if override:
        return override
    return getpass("Contraseña general: ")


def main():

    password = obtener_contrasena()
    try:
        datos_desc = decrypt_generic(DATOS_FILE, password)
    except:
        print(f"❌ Error de contraseña o archivos {DATOS_FILE}")
        return
    try:
        seed_desc = decrypt_generic(SEED_FILE, password)
    except:
        print(f"❌ Error de contraseña o archivos corruptos {SEED_FILE}")
        return
        





    registros = cargar_datos(datos_desc)
    mi_mnemonic = seed_desc.decode().strip()

    while True:
        print("\n===== MENU =====")
        print("1. Consultar balances ALGO")
        print("2. Enviar ASA (según asset_id de cada registro)")
        print("0. Salir")

        opcion = input("Selecciona opción: ")

        if opcion == "1":
            seleccionados = seleccionar_registros(registros)
            consultar_balances(seleccionados)

        elif opcion == "2":
            seleccionados = seleccionar_registros(registros)
            enviar_asa(mi_mnemonic, seleccionados)

        elif opcion == "0":
            print("Saliendo...")
            break

        else:
            print("Opción inválida")

if __name__ == "__main__":
    main()
