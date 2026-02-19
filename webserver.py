import base64
import json
import os
import random
import re
import string
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
from algosdk.transaction import AssetTransferTxn, PaymentTxn
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

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
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", "filencrypt-session-secret"))
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
    auth_value: str
    role: str
    nickname: str


def build_nav(current: str, is_admin_user: bool) -> list[dict]:
    items = [
        {"key": "dashboard", "label": "Principal", "href": "/"},
        {"key": "pantallas", "label": "Pantallas", "href": "/pantallas"},
    ]
    if is_admin_user:
        items.append({"key": "admin_accounts", "label": "Admin", "href": "/admin/accounts"})
    return items


def random_simple_password(length: int = 8) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


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
        if len(parts) < 4:
            continue

        credito, nombre, direccion, asset_raw = parts[0], parts[1], parts[2], parts[3]
        auth_raw = parts[4] if len(parts) >= 5 else "user"
        nickname_raw = parts[5] if len(parts) >= 6 else ""
        if not encoding.is_valid_address(direccion):
            continue

        try:
            asset_id = int(asset_raw)
        except ValueError:
            asset_id = None

        auth_value = auth_raw.strip() if auth_raw.strip() else "user"
        role = "admin" if auth_value == "admin" else "user"
        nickname = nickname_raw.strip()

        registros.append(
            Registro(
                credito=credito,
                nombre=nombre,
                direccion=direccion,
                asset_id=asset_id,
                auth_value=auth_value,
                role=role,
                nickname=nickname,
            )
        )

    return registros


def load_auth_by_address() -> dict[str, tuple[str, str, str, str]]:
    auth_map: dict[str, tuple[str, str, str, str]] = {}
    if not DIRECCIONES_FILE.exists():
        return auth_map
    raw = DIRECCIONES_FILE.read_text(encoding="utf-8")
    for registro in parse_registros(raw):
        auth_map[registro.direccion] = (registro.auth_value, registro.role, registro.nombre, registro.nickname)
    return auth_map


def get_current_user(request: Request) -> Optional[dict]:
    user = request.session.get("auth_user")
    role = request.session.get("auth_role")
    address = request.session.get("auth_address")
    if not user or not role:
        return None
    return {"user": user, "role": role, "address": address or ""}


def require_login(request: Request) -> Optional[RedirectResponse]:
    if get_current_user(request):
        return None
    return RedirectResponse("/login?error=" + quote_plus("Inicia sesion primero"), status_code=303)


def is_admin(request: Request) -> bool:
    current = get_current_user(request)
    return bool(current and current.get("role") == "admin")


def find_registro_by_address(registros: list[Registro], address: str) -> Optional[Registro]:
    return next((r for r in registros if r.direccion == address), None)


def mnemonic_file_for_registro(registro: Registro) -> Optional[Path]:
    if not registro.nickname.strip():
        return None
    nickname_clean = sanitize_nickname(registro.nickname)
    if not nickname_clean:
        return None
    return Path(f"palabras.{nickname_clean}.txt")


def discover_seed_file_by_address(address: str) -> Optional[Path]:
    for seed_file in sorted(Path(".").glob("palabras.*.txt")):
        try:
            mnemonic_text = seed_file.read_text(encoding="utf-8").strip()
            if not mnemonic_text:
                continue
            _, seed_address = mnemonic_to_account(mnemonic_text)
            if seed_address == address:
                return seed_file
        except Exception:
            continue
    return None


def resolve_seed_file_for_registro(registro: Registro) -> Optional[Path]:
    preferred = mnemonic_file_for_registro(registro)
    if preferred and preferred.exists():
        return preferred
    discovered = discover_seed_file_by_address(registro.direccion)
    if discovered:
        return discovered
    return preferred


def session_user_can_transact(
    request: Request, registros: Optional[list[Registro]] = None
) -> tuple[bool, Optional[Registro], str]:
    current_user = get_current_user(request)
    if not current_user:
        return False, None, "Inicia sesion primero"

    if registros is None:
        registros, _ = load_registros()
    registro = find_registro_by_address(registros, current_user.get("address", ""))
    if not registro:
        return False, None, "No se encontro la cuenta del usuario logueado"

    seed_file = resolve_seed_file_for_registro(registro)
    if seed_file is None:
        return False, registro, "Cuenta sin seed de 25 palabras para operar"
    if not seed_file.exists():
        return False, registro, f"No existe {seed_file.name} para esta cuenta"
    return True, registro, ""


def load_session_sender_account(
    request: Request, mnemonic_override: str = ""
) -> tuple[str, str, Registro]:
    registros, _ = load_registros()
    can_transact, registro, reason = session_user_can_transact(request, registros)
    if not can_transact or registro is None:
        raise ValueError(reason or "Cuenta sin permisos de operacion")

    if mnemonic_override.strip():
        mnemonic_text = mnemonic_override.strip()
        seed_label = "mnemonic manual"
    else:
        seed_file = resolve_seed_file_for_registro(registro)
        if seed_file is None:
            raise ValueError("Cuenta sin archivo de seed")
        mnemonic_text = seed_file.read_text(encoding="utf-8").strip()
        seed_label = seed_file.name

    if not mnemonic_text:
        raise ValueError("Mnemonic vacio")

    private_key, sender_address = mnemonic_to_account(mnemonic_text)
    if sender_address != registro.direccion:
        raise ValueError(f"La seed ({seed_label}) no corresponde a la direccion del usuario logueado")
    return private_key, sender_address, registro


def sanitize_nickname(raw_value: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9_-]+", "_", raw_value.strip())
    clean = re.sub(r"_+", "_", clean).strip("_")
    return clean


def append_registro_line(
    credito: str,
    nombre: str,
    direccion: str,
    asset_id: int,
    auth_value: str,
    nickname: str,
) -> None:
    line = f"{credito};{nombre};{direccion};{asset_id};{auth_value};{nickname}"
    with DIRECCIONES_FILE.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


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
    auth_map = load_auth_by_address()

    if password and DATOS_FILE.exists():
        try:
            decrypted = decrypt_file(DATOS_FILE, password).decode("utf-8")
            registros = parse_registros(decrypted)
            for r in registros:
                if r.direccion in auth_map:
                    auth_value, role, nombre, nickname = auth_map[r.direccion]
                    r.auth_value = auth_value
                    r.role = role
                    if nombre:
                        r.nombre = nombre
                    if nickname:
                        r.nickname = nickname
            return registros, "datos.txt (descifrado)"
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


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    registros, _ = load_registros()
    users = []
    seen = set()
    for r in registros:
        key = (r.nombre, r.direccion)
        if key in seen:
            continue
        seen.add(key)
        users.append({"nombre": r.nombre, "direccion": r.direccion, "role": r.role})
    users.sort(key=lambda x: x["nombre"])
    error = request.query_params.get("error", "")
    message = request.query_params.get("message", "")
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "users": users,
            "error": error,
            "message": message,
        },
    )


@app.post("/login")
def do_login(request: Request, address: str = Form(...), password: str = Form(...)):
    registros, _ = load_registros()
    for r in registros:
        if r.direccion == address and r.auth_value == password:
            request.session["auth_user"] = r.nombre
            request.session["auth_role"] = r.role
            request.session["auth_address"] = r.direccion
            return RedirectResponse("/?message=" + quote_plus(f"Sesion iniciada como {r.nombre}"), status_code=303)
    return RedirectResponse("/login?error=" + quote_plus("Credenciales invalidas"), status_code=303)


@app.post("/logout")
def do_logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login?message=" + quote_plus("Sesion cerrada"), status_code=303)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    redirect = require_login(request)
    if redirect:
        return redirect

    current_user = get_current_user(request)
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
            "nav_items": build_nav("dashboard", is_admin(request)),
            "current_view": "dashboard",
            "current_user": current_user,
            "is_admin": bool(current_user and current_user.get("role") == "admin"),
        },
    )


@app.get("/pantallas", response_class=HTMLResponse)
def screens(request: Request):
    redirect = require_login(request)
    if redirect:
        return redirect
    current_user = get_current_user(request)
    return templates.TemplateResponse(
        request,
        "screens.html",
        {
            "nav_items": build_nav("pantallas", is_admin(request)),
            "current_view": "pantallas",
            "current_user": current_user,
        },
    )


@app.get("/admin/accounts", response_class=HTMLResponse)
def admin_accounts_page(request: Request):
    redirect = require_login(request)
    if redirect:
        return redirect
    if not is_admin(request):
        return RedirectResponse("/?error=" + quote_plus("Solo admin"), status_code=303)

    current_user = get_current_user(request)
    registros, _ = load_registros()
    message = request.query_params.get("message", "")
    error = request.query_params.get("error", "")
    return templates.TemplateResponse(
        request,
        "admin_accounts.html",
        {
            "nav_items": build_nav("admin_accounts", True),
            "current_view": "admin_accounts",
            "current_user": current_user,
            "message": message,
            "error": error,
            "registros": registros,
        },
    )


@app.post("/admin/accounts/create")
def admin_accounts_create(
    request: Request,
    credito: str = Form(...),
    nombre: str = Form(...),
    asset_id: int = Form(...),
    auth_value: str = Form(""),
    nickname: str = Form(...),
):
    redirect = require_login(request)
    if redirect:
        return redirect
    if not is_admin(request):
        return RedirectResponse("/?error=" + quote_plus("Solo admin"), status_code=303)

    if asset_id <= 0:
        return RedirectResponse("/admin/accounts?error=" + quote_plus("asset_id invalido"), status_code=303)

    nickname_clean = sanitize_nickname(nickname)
    if not nickname_clean:
        return RedirectResponse("/admin/accounts?error=" + quote_plus("nickname invalido"), status_code=303)

    seed_file = Path(f"palabras.{nickname_clean}.txt")
    if seed_file.exists():
        return RedirectResponse(
            "/admin/accounts?error=" + quote_plus(f"Ya existe {seed_file.name}"),
            status_code=303,
        )

    effective_auth = auth_value.strip() if auth_value.strip() else random_simple_password(8)
    private_key, address = account.generate_account()
    mnemonic_25 = algo_mnemonic.from_private_key(private_key)

    try:
        seed_file.write_text(mnemonic_25 + "\n", encoding="utf-8")
        append_registro_line(
            credito=credito.strip(),
            nombre=nombre.strip(),
            direccion=address,
            asset_id=asset_id,
            auth_value=effective_auth,
            nickname=nickname_clean,
        )
        password = os.getenv("LISTA_PASSWORD", "").strip()
        if not password:
            return RedirectResponse(
                "/admin/accounts?message="
                + quote_plus(
                    f"Cuenta creada {nombre.strip()} | addr={address} | pass={effective_auth} | "
                    f"seed={seed_file.name}. AVISO: no se recifro datos.txt (falta LISTA_PASSWORD)"
                ),
                status_code=303,
            )
        encrypt_file(DIRECCIONES_FILE, DATOS_FILE, password)
        _balance_cache.clear()
        _call_timestamps.clear()
        return RedirectResponse(
            "/admin/accounts?message="
            + quote_plus(
                f"Cuenta creada {nombre.strip()} | addr={address} | pass={effective_auth} | "
                f"seed={seed_file.name} | datos.txt recifrado"
            ),
            status_code=303,
        )
    except Exception as exc:
        return RedirectResponse("/admin/accounts?error=" + quote_plus(str(exc)), status_code=303)


@app.post("/encrypt-datos")
def encrypt_datos(request: Request, password_override: str = Form("")):
    redirect = require_login(request)
    if redirect:
        return redirect
    if not is_admin(request):
        return RedirectResponse("/?error=" + quote_plus("Solo admin puede cifrar"), status_code=303)

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
    redirect = require_login(request)
    if redirect:
        return redirect

    if not encoding.is_valid_address(address):
        return RedirectResponse("/?error=" + quote_plus("Direccion invalida"), status_code=303)

    current_user = get_current_user(request)

    client = algod.AlgodClient(ALGOD_TOKEN, ALGOD_ADDRESS)
    registros, _ = load_registros()
    current = next((r for r in registros if r.direccion == address), None)
    selected_asset = request.query_params.get("asset_id", "")
    message = request.query_params.get("message", "")
    error = request.query_params.get("error", "")

    sender_address = ""
    sender_name = "No identificado"
    sender_algo_balance = 0.0
    sender_block_reason = ""
    can_transact = False
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

        can_transact, sender_registro, sender_block_reason = session_user_can_transact(request, registros)
        if can_transact and sender_registro:
            sender_address = sender_registro.direccion
            sender_name = sender_registro.nombre
            sender_info = client.account_info(sender_address)
            sender_algo_balance = sender_info.get("amount", 0) / 1_000_000
            for sender_asset in sender_info.get("assets", []):
                sender_asset_id = sender_asset.get("asset-id")
                if sender_asset_id is None:
                    continue
                sender_assets_by_id[sender_asset_id] = sender_asset.get("amount", 0)
            for option in send_asset_options:
                option["available"] = sender_assets_by_id.get(option["asset_id"], 0)
                option["available_human"] = base_to_human(option["available"], option["decimals"])
        else:
            for option in send_asset_options:
                option["available"] = 0
                option["available_human"] = "0"

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
            "sender_algo_balance": sender_algo_balance,
            "can_transact": can_transact,
            "sender_block_reason": sender_block_reason,
            "message": message,
            "error": error,
            "selected_asset": selected_asset,
            "nav_items": build_nav("dashboard", is_admin(request)),
            "current_view": "dashboard",
            "current_user": current_user,
        },
    )


@app.post("/send-asa")
def send_asa(
    request: Request,
    destination: str = Form(...),
    asset_id: int = Form(...),
    amount: str = Form(...),
    mnemonic_override: str = Form(""),
):
    redirect = require_login(request)
    if redirect:
        return redirect
    can_transact, _, reason = session_user_can_transact(request)
    if not can_transact:
        return RedirectResponse(
            f"/address/{destination}?error=" + quote_plus(reason or "No autorizado"),
            status_code=303,
        )

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
        private_key, sender, _ = load_session_sender_account(request, mnemonic_override)
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


@app.post("/send-algo")
def send_algo(
    request: Request,
    destination: str = Form(...),
    amount: str = Form(...),
    mnemonic_override: str = Form(""),
):
    redirect = require_login(request)
    if redirect:
        return redirect
    can_transact, _, reason = session_user_can_transact(request)
    if not can_transact:
        return RedirectResponse(
            f"/address/{destination}?error=" + quote_plus(reason or "No autorizado"),
            status_code=303,
        )

    if not encoding.is_valid_address(destination):
        return RedirectResponse("/?error=" + quote_plus("Direccion destino invalida"), status_code=303)

    client = algod.AlgodClient(ALGOD_TOKEN, ALGOD_ADDRESS)
    try:
        amount_microalgos = human_to_base(amount, 6)
        private_key, sender, _ = load_session_sender_account(request, mnemonic_override)
        sender_info = client.account_info(sender)
        available_microalgos = int(sender_info.get("amount", 0))
        params = client.suggested_params()
        fee_microalgos = int(params.min_fee or 1000)

        if amount_microalgos + fee_microalgos > available_microalgos:
            return RedirectResponse(
                f"/address/{destination}?error="
                + quote_plus(
                    "Cantidad ALGO supera saldo disponible (incluyendo fee). "
                    f"Disponible: {base_to_human(available_microalgos, 6)} ALGO"
                ),
                status_code=303,
            )

        txn = PaymentTxn(
            sender=sender,
            sp=params,
            receiver=destination,
            amt=amount_microalgos,
        )
        signed_txn = txn.sign(private_key)
        txid = client.send_transaction(signed_txn)
        return RedirectResponse(
            f"/address/{destination}?message="
            + quote_plus(f"Envio ALGO correcto {amount} (microalgos {amount_microalgos}). TXID: {txid}"),
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
    request: Request,
    asset_id: int = Form(...),
    owner_address: str = Form(...),
):
    redirect = require_login(request)
    if redirect:
        return redirect
    can_transact, _, reason = session_user_can_transact(request)
    if not can_transact:
        return RedirectResponse(
            f"/address/{owner_address}?error=" + quote_plus(reason or "No autorizado"),
            status_code=303,
        )

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
        target_private_key, target_address, _ = load_session_sender_account(request, "")
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
