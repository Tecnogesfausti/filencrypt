import base64
import json
import os
import time
from os import urandom
from collections import deque
from dataclasses import dataclass
from decimal import Decimal, ROUND_DOWN, InvalidOperation
from pathlib import Path
from typing import Optional
from urllib.parse import quote_plus

from algosdk import encoding
from algosdk import account
from algosdk import mnemonic as algo_mnemonic
from algosdk.v2client import algod
from algosdk.transaction import AssetTransferTxn
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

DATOS_FILE = Path("datos.txt")
DIRECCIONES_FILE = Path("direcciones.txt")
SEED_FILE = Path("seed.txt")
SALT_FILE = Path("salt.bin")
ASSET_MAP_FILE = Path("asset_map.json")

ALGOD_ADDRESS = os.getenv("ALGOD_ADDRESS", "https://mainnet-api.algonode.cloud")
ALGOD_TOKEN = os.getenv("ALGOD_TOKEN", "")
API_RATE_LIMIT_PER_MIN = int(os.getenv("API_RATE_LIMIT_PER_MIN", "5"))
BALANCE_CACHE_TTL_SECONDS = int(os.getenv("BALANCE_CACHE_TTL_SECONDS", "180"))

app = FastAPI(title="Wallet Dashboard")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

_balance_cache: dict[str, dict] = {}
_call_timestamps: deque[float] = deque()


@dataclass
class Registro:
    credito: str
    nombre: str
    direccion: str
    asset_id: Optional[int]


def build_nav(current: str) -> list[dict]:
    return [
        {"key": "dashboard", "label": "Principal", "href": "/"},
        {"key": "pantallas", "label": "Pantallas", "href": "/pantallas"},
    ]


def salt_file_for(encrypted_file: Path) -> Path:
    return Path(f"{encrypted_file}.salt")


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def decrypt_file(file_path: Path, password: str) -> bytes:
    salt_path = salt_file_for(file_path)
    if salt_path.exists():
        salt = salt_path.read_bytes()
    else:
        salt = SALT_FILE.read_bytes()

    key = derive_key(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(file_path.read_bytes())


def encrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    salt = urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(input_path.read_bytes())
    output_path.write_bytes(encrypted)
    salt_file_for(output_path).write_bytes(salt)


def parse_registros(raw_text: str) -> list[Registro]:
    registros: list[Registro] = []
    for line in raw_text.splitlines():
        parts = [part.strip() for part in line.split(";")]
        if len(parts) != 4:
            continue

        credito, nombre, direccion, asset_raw = parts
        if not encoding.is_valid_address(direccion):
            continue

        try:
            asset_id = int(asset_raw)
        except ValueError:
            asset_id = None

        registros.append(
            Registro(
                credito=credito,
                nombre=nombre,
                direccion=direccion,
                asset_id=asset_id,
            )
        )

    return registros


def load_asset_map() -> dict[int, dict]:
    if not ASSET_MAP_FILE.exists():
        return {}
    try:
        raw = json.loads(ASSET_MAP_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}

    out: dict[int, dict] = {}
    for key, value in raw.items():
        try:
            asset_id = int(key)
        except (TypeError, ValueError):
            continue
        if isinstance(value, str):
            out[asset_id] = {"alias": value}
            continue
        if isinstance(value, dict):
            out[asset_id] = {
                "alias": str(value.get("alias", "")).strip(),
                "name": str(value.get("name", "")).strip(),
                "unit_name": str(value.get("unit_name", "")).strip(),
                "decimals": value.get("decimals"),
            }
    return out


def save_asset_map(asset_map: dict[int, dict]) -> None:
    serializable = {str(k): v for k, v in sorted(asset_map.items(), key=lambda x: x[0])}
    ASSET_MAP_FILE.write_text(json.dumps(serializable, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def asset_label(asset_id: int, meta: Optional[dict]) -> str:
    meta = meta or {}
    alias = str(meta.get("alias", "")).strip()
    unit_name = str(meta.get("unit_name", "")).strip()
    name = str(meta.get("name", "")).strip()
    if alias:
        return f"{alias} ({asset_id})"
    if unit_name:
        return f"{unit_name} ({asset_id})"
    if name:
        return f"{name} ({asset_id})"
    return f"ASA {asset_id}"


def get_asset_meta(client: algod.AlgodClient, asset_map: dict[int, dict], asset_id: int) -> tuple[dict, bool]:
    existing = asset_map.get(asset_id, {})
    meta = {
        "alias": str(existing.get("alias", "")).strip(),
        "name": str(existing.get("name", "")).strip(),
        "unit_name": str(existing.get("unit_name", "")).strip(),
        "decimals": existing.get("decimals"),
    }
    changed = asset_id not in asset_map

    should_fetch = not meta["name"] and not meta["unit_name"]
    if should_fetch:
        try:
            params = client.asset_info(asset_id).get("params", {})
            fetched_name = str(params.get("name", "")).strip()
            fetched_unit = str(params.get("unit-name", "")).strip()
            fetched_decimals = params.get("decimals")
            if fetched_name and fetched_name != meta["name"]:
                meta["name"] = fetched_name
                changed = True
            if fetched_unit and fetched_unit != meta["unit_name"]:
                meta["unit_name"] = fetched_unit
                changed = True
            if fetched_decimals != meta["decimals"]:
                meta["decimals"] = fetched_decimals
                changed = True
        except Exception:
            pass

    if changed:
        asset_map[asset_id] = meta
    return meta, changed


def normalize_decimals(decimals_value: Optional[int]) -> int:
    try:
        decimals_int = int(decimals_value)
    except (TypeError, ValueError):
        return 0
    return max(decimals_int, 0)


def base_to_human(base_amount: int, decimals: int) -> str:
    dec = normalize_decimals(decimals)
    factor = Decimal(10) ** dec
    value = (Decimal(base_amount) / factor).normalize()
    text = format(value, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def human_to_base(human_amount_text: str, decimals: int) -> int:
    dec = normalize_decimals(decimals)
    amount_text = human_amount_text.strip().replace(",", ".")
    human_value = Decimal(amount_text)
    if human_value <= 0:
        raise ValueError("Cantidad debe ser mayor que cero")
    factor = Decimal(10) ** dec
    base_value = (human_value * factor).quantize(Decimal("1"), rounding=ROUND_DOWN)
    if base_value <= 0:
        raise ValueError("Cantidad demasiado pequena para los decimales del asset")
    return int(base_value)


def load_registros() -> tuple[list[Registro], str]:
    password = os.getenv("LISTA_PASSWORD", "")

    if password and DATOS_FILE.exists():
        try:
            decrypted = decrypt_file(DATOS_FILE, password).decode("utf-8")
            return parse_registros(decrypted), "datos.txt (descifrado)"
        except (InvalidToken, UnicodeDecodeError, FileNotFoundError):
            pass

    if DIRECCIONES_FILE.exists():
        return parse_registros(DIRECCIONES_FILE.read_text(encoding="utf-8")), "direcciones.txt"

    return [], "sin datos"


def fetch_balances(registros: list[Registro]) -> tuple[list[dict], int, int]:
    client = algod.AlgodClient(ALGOD_TOKEN, ALGOD_ADDRESS)
    asset_map = load_asset_map()
    asset_map_changed = False
    meta_cache: dict[int, dict] = {}
    rows: list[dict] = []
    ok = 0
    fail = 0
    now = time.time()

    while _call_timestamps and now - _call_timestamps[0] > 60:
        _call_timestamps.popleft()

    for item in registros:
        row = {
            "credito": item.credito,
            "nombre": item.nombre,
            "direccion": item.direccion,
            "asset_id": item.asset_id,
            "balance": None,
            "asa_count": 0,
            "assets_preview": [],
            "asset_label": "-",
            "error": None,
        }
        if item.asset_id is not None:
            meta = asset_map.get(item.asset_id, {})
            row["asset_label"] = asset_label(item.asset_id, meta)

        cached = _balance_cache.get(item.direccion)
        cache_fresh = cached and (now - cached["ts"] <= BALANCE_CACHE_TTL_SECONDS)
        if cache_fresh:
            row["balance"] = cached["balance"]
            row["asa_count"] = cached["asa_count"]
            row["assets_preview"] = cached["assets_preview"]
            row["error"] = cached["error"]
            row["asset_label"] = cached.get("asset_label", row["asset_label"])
        else:
            if len(_call_timestamps) >= API_RATE_LIMIT_PER_MIN:
                if cached:
                    row["balance"] = cached["balance"]
                    row["asa_count"] = cached["asa_count"]
                    row["assets_preview"] = cached["assets_preview"]
                    row["error"] = "Dato en cache (limite API alcanzado)"
                    row["asset_label"] = cached.get("asset_label", row["asset_label"])
                else:
                    row["error"] = "Pendiente (limite API alcanzado)"
            else:
                try:
                    info = client.account_info(item.direccion)
                    row["balance"] = info.get("amount", 0) / 1_000_000
                    assets = info.get("assets", [])
                    row["asa_count"] = len(assets)
                    preview = []
                    for asa in assets:
                        amount = asa.get("amount", 0)
                        asset_id = asa.get("asset-id")
                        if amount and asset_id is not None:
                            if asset_id in meta_cache:
                                meta = meta_cache[asset_id]
                            else:
                                meta, changed = get_asset_meta(client, asset_map, asset_id)
                                meta_cache[asset_id] = meta
                                asset_map_changed = asset_map_changed or changed
                            preview.append(f"{asset_label(asset_id, meta)}:{amount}")
                        if len(preview) >= 3:
                            break
                    row["assets_preview"] = preview
                    if item.asset_id is not None:
                        if item.asset_id in meta_cache:
                            item_meta = meta_cache[item.asset_id]
                        else:
                            item_meta, changed = get_asset_meta(client, asset_map, item.asset_id)
                            meta_cache[item.asset_id] = item_meta
                            asset_map_changed = asset_map_changed or changed
                        row["asset_label"] = asset_label(item.asset_id, item_meta)
                except Exception as exc:  # network/provider errors
                    row["error"] = str(exc)
                _balance_cache[item.direccion] = {
                    "balance": row["balance"],
                    "asa_count": row["asa_count"],
                    "assets_preview": row["assets_preview"],
                    "asset_label": row["asset_label"],
                    "error": row["error"],
                    "ts": time.time(),
                }
                _call_timestamps.append(time.time())

        if row["error"]:
            fail += 1
        else:
            ok += 1
        rows.append(row)

    rows.sort(key=lambda x: x["nombre"])
    if asset_map_changed:
        save_asset_map(asset_map)
    return rows, ok, fail


def load_sender_mnemonic(mnemonic_override: str = "") -> str:
    if mnemonic_override.strip():
        return mnemonic_override.strip()

    env_mnemonic = os.getenv("SENDER_MNEMONIC", "").strip()
    if env_mnemonic:
        return env_mnemonic

    password = os.getenv("LISTA_PASSWORD", "")
    if not password:
        raise ValueError("Falta LISTA_PASSWORD para descifrar seed.txt")
    if not SEED_FILE.exists():
        raise ValueError("No existe seed.txt")

    try:
        return decrypt_file(SEED_FILE, password).decode("utf-8").strip()
    except Exception as exc:
        raise ValueError(f"No se pudo descifrar seed.txt: {exc}") from exc


def mnemonic_to_account(mnemonic_text: str) -> tuple[str, str]:
    private_key = algo_mnemonic.to_private_key(mnemonic_text.strip())
    address = account.address_from_private_key(private_key)
    return private_key, address


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    registros, source = load_registros()
    rows, ok_count, fail_count = fetch_balances(registros) if registros else ([], 0, 0)
    message = request.query_params.get("message", "")
    error = request.query_params.get("error", "")

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "source": source,
            "rows": rows,
            "total": len(rows),
            "ok_count": ok_count,
            "fail_count": fail_count,
            "message": message,
            "error": error,
            "nav_items": build_nav("dashboard"),
            "current_view": "dashboard",
        },
    )


@app.get("/pantallas", response_class=HTMLResponse)
def screens(request: Request):
    return templates.TemplateResponse(
        request,
        "screens.html",
        {
            "nav_items": build_nav("pantallas"),
            "current_view": "pantallas",
        },
    )


@app.post("/encrypt-datos")
def encrypt_datos(password_override: str = Form("")):
    password = password_override.strip() or os.getenv("LISTA_PASSWORD", "").strip()
    if not password:
        return RedirectResponse("/?error=" + quote_plus("Falta contrasena para cifrar"), status_code=303)
    if not DIRECCIONES_FILE.exists():
        return RedirectResponse("/?error=" + quote_plus("No existe direcciones.txt"), status_code=303)

    try:
        encrypt_file(DIRECCIONES_FILE, DATOS_FILE, password)
        _balance_cache.clear()
        _call_timestamps.clear()
        return RedirectResponse(
            "/?message=" + quote_plus("direcciones.txt cifrado correctamente en datos.txt"),
            status_code=303,
        )
    except Exception as exc:
        return RedirectResponse("/?error=" + quote_plus(str(exc)), status_code=303)


@app.get("/address/{address}", response_class=HTMLResponse)
def address_detail(request: Request, address: str):
    if not encoding.is_valid_address(address):
        return RedirectResponse("/?error=" + quote_plus("Direccion invalida"), status_code=303)

    client = algod.AlgodClient(ALGOD_TOKEN, ALGOD_ADDRESS)
    registros, _ = load_registros()
    current = next((r for r in registros if r.direccion == address), None)
    selected_asset = request.query_params.get("asset_id", "")
    message = request.query_params.get("message", "")
    error = request.query_params.get("error", "")

    sender_address = ""
    sender_name = "No identificado"
    sender_assets_by_id: dict[int, int] = {}

    try:
        info = client.account_info(address)
        algo_balance = info.get("amount", 0) / 1_000_000
        asset_map = load_asset_map()
        asset_map_changed = False
        assets = []
        for item in info.get("assets", []):
            asset_id = item.get("asset-id")
            if asset_id is None:
                continue
            meta, changed = get_asset_meta(client, asset_map, asset_id)
            asset_map_changed = asset_map_changed or changed
            assets.append(
                {
                    "asset_id": asset_id,
                    "label": asset_label(asset_id, meta),
                    "name": meta.get("name", ""),
                    "unit_name": meta.get("unit_name", ""),
                    "decimals": meta.get("decimals"),
                    "alias": meta.get("alias", ""),
                    "amount_base": item.get("amount", 0),
                    "amount_human": base_to_human(item.get("amount", 0), normalize_decimals(meta.get("decimals"))),
                    "is_frozen": item.get("is-frozen", False),
                }
            )
        assets.sort(key=lambda x: x["amount_base"], reverse=True)
        available_ids = {row["asset_id"] for row in assets}
        available_ids.update(asset_map.keys())
        send_asset_options = []
        for asset_id in sorted(available_ids):
            meta, changed = get_asset_meta(client, asset_map, asset_id)
            asset_map_changed = asset_map_changed or changed
            send_asset_options.append(
                {
                    "asset_id": asset_id,
                    "label": asset_label(asset_id, meta),
                    "decimals": normalize_decimals(meta.get("decimals")),
                    "available": sender_assets_by_id.get(asset_id, 0),
                }
            )

        sender_mnemonic = load_sender_mnemonic("")
        sender_private_key = algo_mnemonic.to_private_key(sender_mnemonic)
        sender_address = account.address_from_private_key(sender_private_key)
        sender_registro = next((r for r in registros if r.direccion == sender_address), None)
        if sender_registro:
            sender_name = sender_registro.nombre
        sender_info = client.account_info(sender_address)
        for sender_asset in sender_info.get("assets", []):
            sender_asset_id = sender_asset.get("asset-id")
            if sender_asset_id is None:
                continue
            sender_assets_by_id[sender_asset_id] = sender_asset.get("amount", 0)
        for option in send_asset_options:
            option["available"] = sender_assets_by_id.get(option["asset_id"], 0)
            option["available_human"] = base_to_human(option["available"], option["decimals"])

        if asset_map_changed:
            save_asset_map(asset_map)
    except Exception as exc:
        return RedirectResponse("/?error=" + quote_plus(str(exc)), status_code=303)

    return templates.TemplateResponse(
        request,
        "address.html",
        {
            "address": address,
            "name": current.nombre if current else "Sin nombre",
            "credito": current.credito if current else "-",
            "algo_balance": algo_balance,
            "assets": assets,
            "send_asset_options": send_asset_options,
            "sender_address": sender_address,
            "sender_name": sender_name,
            "message": message,
            "error": error,
            "selected_asset": selected_asset,
            "nav_items": build_nav("dashboard"),
            "current_view": "dashboard",
        },
    )


@app.post("/send-asa")
def send_asa(
    destination: str = Form(...),
    asset_id: int = Form(...),
    amount: str = Form(...),
    mnemonic_override: str = Form(""),
):
    if not encoding.is_valid_address(destination):
        return RedirectResponse("/?error=" + quote_plus("Direccion destino invalida"), status_code=303)

    client = algod.AlgodClient(ALGOD_TOKEN, ALGOD_ADDRESS)
    asset_map = load_asset_map()
    if asset_id not in asset_map:
        return RedirectResponse(
            f"/address/{destination}?error=" + quote_plus("Asset no encontrado en mapeo interno"),
            status_code=303,
        )

    try:
        decimals = normalize_decimals(asset_map.get(asset_id, {}).get("decimals"))
        amount_base = human_to_base(amount, decimals)
        mnemonic_text = load_sender_mnemonic(mnemonic_override)
        private_key, sender = mnemonic_to_account(mnemonic_text)
        sender_info = client.account_info(sender)
        available = 0
        for sender_asset in sender_info.get("assets", []):
            if sender_asset.get("asset-id") == asset_id:
                available = sender_asset.get("amount", 0)
                break
        if amount_base > available:
            return RedirectResponse(
                f"/address/{destination}?error="
                + quote_plus(
                    "Cantidad supera saldo disponible. "
                    f"Disponible: {base_to_human(available, decimals)} ({available} base)"
                ),
                status_code=303,
            )
        params = client.suggested_params()
        txn = AssetTransferTxn(
            sender=sender,
            sp=params,
            receiver=destination,
            amt=amount_base,
            index=asset_id,
        )
        signed_txn = txn.sign(private_key)
        txid = client.send_transaction(signed_txn)
        return RedirectResponse(
            f"/address/{destination}?message="
            + quote_plus(f"Envio correcto {amount} (base {amount_base}). TXID: {txid}"),
            status_code=303,
        )
    except (InvalidOperation, ValueError) as exc:
        return RedirectResponse(
            f"/address/{destination}?error=" + quote_plus(str(exc)),
            status_code=303,
        )
    except Exception as exc:
        return RedirectResponse(
            f"/address/{destination}?error=" + quote_plus(str(exc)),
            status_code=303,
        )


@app.post("/optin-asa")
def optin_asa(
    asset_id: int = Form(...),
    owner_address: str = Form(...),
):
    if not encoding.is_valid_address(owner_address):
        return RedirectResponse("/?error=" + quote_plus("Direccion de detalle invalida"), status_code=303)

    client = algod.AlgodClient(ALGOD_TOKEN, ALGOD_ADDRESS)
    asset_map = load_asset_map()
    if asset_id not in asset_map:
        return RedirectResponse(
            f"/address/{owner_address}?error=" + quote_plus("Asset no encontrado en mapeo interno"),
            status_code=303,
        )

    try:
        sender_mnemonic = load_sender_mnemonic("")
        target_private_key, target_address = mnemonic_to_account(sender_mnemonic)
        target_info = client.account_info(target_address)
        for holding in target_info.get("assets", []):
            if holding.get("asset-id") == asset_id:
                return RedirectResponse(
                    f"/address/{owner_address}?message="
                    + quote_plus(f"La cuenta {target_address} ya estaba opt-in para ese asset"),
                    status_code=303,
                )

        params = client.suggested_params()
        txn = AssetTransferTxn(
            sender=target_address,
            sp=params,
            receiver=target_address,
            amt=0,
            index=asset_id,
        )
        signed_txn = txn.sign(target_private_key)
        txid = client.send_transaction(signed_txn)
        return RedirectResponse(
            f"/address/{owner_address}?message="
            + quote_plus(f"Opt-in correcto en {target_address}. TXID: {txid}"),
            status_code=303,
        )
    except Exception as exc:
        return RedirectResponse(
            f"/address/{owner_address}?error=" + quote_plus(str(exc)),
            status_code=303,
        )
