Wallet / Filencrypt - Notas Operativas
=====================================

Estado actual
-------------
- Webserver activo con FastAPI en `webserver.py`.
- Arranque recomendado persistente con `systemd --user` (unit file versionado en `systemd/filencrypt-web.service`).
- Login por usuario/clave habilitado (`/login`) con sesion.
  - el selector usa direccion (unica) y muestra nombre/rol.
- Roles:
  - `admin`: acceso a pantallas admin (crear cuentas, recifrar datos)
  - `user`: uso normal de alumno
  - envio ALGO/ASA y opt-in dependen de tener seed local `palabras.<nickname>.txt`
- Pantalla admin de cuentas: `/admin/accounts`
  - genera cuenta Algorand nueva (25 palabras)
  - guarda seed en `palabras.<nickname>.txt`
  - añade registro en `direcciones.txt`
  - si `Password login` queda vacio, genera clave simple aleatoria
- Archivos cifrados con salt por archivo:
  - `datos.txt.salt`
  - `seed.txt.salt`
- Verificado funcionando el 2026-02-16:
  - servicio `filencrypt-web.service` en estado `active (running)`
  - acceso LAN: `http://<LAN_IP>:8000/` (IP cambia segun red WiFi)

Cambios recientes recordatorio
------------------------------
- `fen.py`: ahora guarda salt por archivo (`<archivo>.salt`) para evitar romper descifrado entre archivos.
- `lista.py`: descifrado con prioridad de `<archivo>.salt` y fallback a `salt.bin`.
- `lista.py`: `cargar_datos` ignora filas con `asset_id` no numerico para evitar `ValueError`.
- `direcciones.txt` admite 6 campos:
  - `credito;nombre;direccion;asset_id;auth;nickname`
  - `admin` => rol admin, password `admin`
  - cualquier otro valor => rol user y se usa como password de login
- se reemplazaron los valores `user` por passwords aleatorios simples (8 chars)
- `webserver.py`: dashboard de balances desde `datos.txt` descifrado o fallback `direcciones.txt`.
- `webserver.py`: el dashboard muestra por cuenta:
  - balance ALGO
  - numero de tokens ASA
  - vista previa con etiqueta legible (`alias|ticker|name + asset_id`)
- Mapeo interno de assets: `asset_map.json`
  - clave: `asset_id`
  - campos: `alias`, `name`, `unit_name`, `decimals`
  - el sistema completa `name/unit_name/decimals` automaticamente desde SDK
  - puedes editar `alias` manualmente para etiquetas propias
  - ejemplo: `"3413906492": {"alias": "FaustiCoin Clase B", ...}`
- Nueva vista detalle por direccion: `/address/<direccion>`
  - lista completa de tokens ASA de la cuenta
  - formulario de envio ASA con:
    - `asset_id` desde mapeo interno (selector)
    - saldo disponible por asset de la cuenta origen (se muestra en el selector)
    - `cantidad`
    - `mnemonic` opcional (si se omite usa `seed.txt` descifrado)
  - muestra cuenta origen (nombre + direccion) usada para firmar
  - valida que `cantidad` no supere el saldo disponible del asset en origen
  - `cantidad` en envio se interpreta en unidad humana (respeta `decimals` del asset)
    y se convierte a unidades base automaticamente
  - opcion de `Opt-in ASA en otra cuenta`:
    - seleccionas asset
    - se usa automaticamente la cuenta emisora configurada (seed actual)
    - se firma transaccion de opt-in (`amt=0`, `sender=receiver=cuenta emisora`)
- Nueva accion web en dashboard:
  - recifrar `direcciones.txt` -> `datos.txt` desde boton/formulario
  - usa contrasena escrita en el formulario o `LISTA_PASSWORD` si se deja vacio
- `webserver.py`: limite local y cache para no exceder el plan de Tatum:
  - `API_RATE_LIMIT_PER_MIN` (default 5)
  - `BALANCE_CACHE_TTL_SECONDS` (default 180)
- Configuracion estable aplicada para evitar `Pendiente (limite API alcanzado)`:
  - `ALGOD_ADDRESS=https://mainnet-api.algonode.cloud`
  - `API_RATE_LIMIT_PER_MIN=120`
- Dependencia adicional para formularios FastAPI:
  - `python-multipart`

Comandos utiles
---------------
Iniciar webserver en background (opcion simple):
LISTA_PASSWORD=<TU_PASSWORD> nohup /home/lego/sensores/wallet/filencrypt/.venv/bin/uvicorn webserver:app --host 0.0.0.0 --port 8000 > webserver.log 2>&1 &

Instalar unit systemd versionado (recomendado):
mkdir -p ~/.config/systemd/user
cp systemd/filencrypt-web.service ~/.config/systemd/user/filencrypt-web.service

Crear entorno local (no subirlo a git):
cp .env.example .env
# Edita .env y pon LISTA_PASSWORD real

Recargar y habilitar servicio:
systemctl --user daemon-reload
systemctl --user enable --now filencrypt-web

Opcional: mantener servicios de usuario vivos tras logout completo:
loginctl enable-linger "$USER"

Estado del servicio:
systemctl --user status filencrypt-web --no-pager

Logs del servicio:
journalctl --user -u filencrypt-web -f

Parar servicio systemd:
systemctl --user stop filencrypt-web

Arrancar manualmente servicio systemd:
systemctl --user start filencrypt-web

Deshabilitar arranque automatico:
systemctl --user disable filencrypt-web

Ver proceso:
pgrep -af "/home/lego/sensores/wallet/filencrypt/.venv/bin/uvicorn webserver:app"

Ver logs:
tail -f webserver.log

Parar proceso:
kill <PID>

Acceso
------
- Local: http://127.0.0.1:8000/
- Red local (actual): http://<LAN_IP>:8000/
- Para saber la IP LAN actual al cambiar de red: `hostname -I`

Publicar en GitHub (modo seguro)
--------------------------------
1. No subas ficheros en claro (`direcciones.txt`, `palabras.txt`) ni secretos (`.env`).
2. Revisa variables en `.env.example` y usa valores reales solo en `.env` local.
3. Inicializa y publica:
   - `git init`
   - `git add .`
   - `git commit -m "Initial secure publish"`
   - `git branch -M main`
   - `git remote add origin <REPO_URL>`
   - `git push -u origin main`

Archivos sensibles (sin contenido)
----------------------------------
- `.env`: variables de entorno privadas (ej. `LISTA_PASSWORD`, endpoints/tokens).
- `direcciones.txt`: listado de cuentas en claro, direcciones, asset por defecto, password de login y nickname.
- `palabras.<nickname>.txt`: mnemónico de 25 palabras de cada cuenta (control total de fondos).
- `seed.txt`: mnemónico cifrado usado por flujos legacy/globales.
- `seed.txt.salt`: salt para derivar la clave de cifrado de `seed.txt`.
- `datos.txt`: versión cifrada de `direcciones.txt` (compartible solo junto a contraseña correcta).
- `datos.txt.salt`: salt para derivar la clave de cifrado de `datos.txt`.
- `salt.bin`: salt legacy (compatibilidad con cifrados antiguos).
- `webserver.log` / logs de `journalctl`: pueden incluir direcciones, errores operativos o metadatos sensibles.
- `asset_map.json`: no contiene claves privadas, pero expone metadatos/mapeos internos de tus assets.

Backup unico cifrado (ZIP)
--------------------------
- Archivo: `backup_sensible_filencrypt.zip`
- Contiene: `.env`, `direcciones.txt`, `datos.txt`, `datos.txt.salt`, `seed.txt`, `seed.txt.salt`, `salt.bin`, `palabras*.txt`
- Password del ZIP: `fausticoin` (misma que `LISTA_PASSWORD`)
- Regenerar backup:
  - `zip -P fausticoin backup_sensible_filencrypt.zip .env direcciones.txt datos.txt datos.txt.salt seed.txt seed.txt.salt salt.bin palabras*.txt`
