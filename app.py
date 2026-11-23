import os
import math
import sqlite3
from datetime import datetime
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, make_response
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "rutabol_scz_2026_clave_segura")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "rutabol.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXT = {"png", "jpg", "jpeg", "webp"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024  # 4 MB max

TARIFAS = {
    "general": 2.50,
    "escolar": 1.00,
    "universitario": 1.50
}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        rol TEXT NOT NULL DEFAULT 'pasajero',
        categoria TEXT NOT NULL DEFAULT 'general',
        rude TEXT,
        cod_est TEXT,
        foto_ref TEXT DEFAULT 'default.png',
        creado_en TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS unidades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        linea TEXT NOT NULL,
        numero_interno TEXT NOT NULL,
        placa TEXT UNIQUE NOT NULL,
        chofer_nombre TEXT NOT NULL,
        capacidad_max INTEGER NOT NULL DEFAULT 22,
        ocupados INTEGER NOT NULL DEFAULT 0,
        recaudacion REAL NOT NULL DEFAULT 0.0,
        lat REAL NOT NULL,
        lon REAL NOT NULL,
        estado TEXT NOT NULL DEFAULT 'operativa'
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS boletos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id INTEGER NOT NULL,
        unidad_id INTEGER NOT NULL,
        categoria TEXT NOT NULL,
        monto REAL NOT NULL,
        tarjeta_ult4 TEXT NOT NULL,
        tipo_emision TEXT NOT NULL DEFAULT 'compra',
        fecha TEXT NOT NULL,
        FOREIGN KEY (usuario_id) REFERENCES usuarios(id),
        FOREIGN KEY (unidad_id) REFERENCES unidades(id)
    )
    """)

    # Usuarios semilla (RF-01, RF-02, RF-03, RF-04)
    cur.execute("SELECT COUNT(*) FROM usuarios")
    if cur.fetchone()[0] == 0:
        ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        usuarios_demo = [
            ("Jhon Alonzo", "jhon@upds.edu.bo", generate_password_hash("Upds123*"),
             "pasajero", "universitario", None, "20241001", "default.png", ahora),
            ("Carlos Mamani (Chofer)", "chofer18@rutabol.bo", generate_password_hash("Chofer123*"),
             "chofer", "general", None, None, "default.png", ahora),
            ("Administrador SCZ", "admin@rutabol.bo", generate_password_hash("Admin123*"),
             "admin", "general", None, None, "default.png", ahora),
        ]
        cur.executemany("""
            INSERT INTO usuarios (nombre, email, password_hash, rol, categoria, rude, cod_est, foto_ref, creado_en)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, usuarios_demo)

    # Unidades semilla en Santa Cruz de la Sierra (RF-05, RF-07)
    cur.execute("SELECT COUNT(*) FROM unidades")
    if cur.fetchone()[0] == 0:
        unidades_demo = [
            ("Linea 18", "INT-104", "4521-SCZ", "Carlos Mamani", 22, 14, 31.50, -17.7833, -63.1821, "operativa"),
            ("Linea 72", "INT-208", "3890-ABC", "Luis Rojas", 20, 19, 42.00, -17.7750, -63.1750, "operativa"),
            ("Linea 05", "INT-015", "5102-XYZ", "Marco Quispe", 25, 8, 16.00, -17.8350, -63.2100, "operativa"),
        ]
        cur.executemany("""
            INSERT INTO unidades (linea, numero_interno, placa, chofer_nombre, capacidad_max, ocupados, recaudacion, lat, lon, estado)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, unidades_demo)

    conn.commit()
    conn.close()


def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Debes iniciar sesion para acceder al sistema.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get("rol") not in roles:
                flash(f"Acceso denegado: esta accion requiere rol {', '.join(roles)}.", "error")
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return decorated
    return decorator


@app.route("/login", methods=["GET", "POST"])
def login():
    ultimo_usuario = request.cookies.get("ultimo_usuario", "")
    tema = request.cookies.get("tema_rutabol", "claro")

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute("SELECT * FROM usuarios WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["nombre"] = user["nombre"]
            session["email"] = user["email"]
            session["rol"] = user["rol"]
            session["categoria"] = user["categoria"]
            session["foto_ref"] = user["foto_ref"] or "default.png"

            resp = make_response(redirect(url_for("index")))
            resp.set_cookie("ultimo_usuario", email, max_age=30 * 24 * 3600)
            if "tema_rutabol" not in request.cookies:
                resp.set_cookie("tema_rutabol", "claro", max_age=30 * 24 * 3600)
            flash(f"Bienvenido, {user['nombre']} ({user['rol'].upper()}).", "ok")
            return resp

        flash("Credenciales invalidas. Verifica tu correo y contrasena.", "error")

    return render_template("login.html", ultimo_usuario=ultimo_usuario, tema=tema)


@app.route("/registro", methods=["GET", "POST"])
def registro():
    tema = request.cookies.get("tema_rutabol", "claro")

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        categoria = request.form.get("categoria", "general")
        rude = request.form.get("rude", "").strip() or None
        cod_est = request.form.get("cod_est", "").strip() or None
        foto = request.files.get("foto")

        if not nombre or not email or len(password) < 6:
            flash("Completa nombre, correo y una contrasena de al menos 6 caracteres.", "error")
            return render_template("registro.html", tema=tema)

        # Validaciones RF-02 y RF-03
        if categoria == "escolar":
            if not rude or len(rude) < 6:
                flash("Para tarifa Escolar (Bs 1.00) debes ingresar un codigo RUDE valido.", "error")
                return render_template("registro.html", tema=tema)
            if not foto or foto.filename == "":
                flash("Para tarifa Escolar debes subir tu fotografia de estudiante.", "error")
                return render_template("registro.html", tema=tema)

        if categoria == "universitario":
            if not email.endswith("@upds.edu.bo"):
                flash("Para tarifa Universitaria (Bs 1.50) el correo debe terminar en @upds.edu.bo.", "error")
                return render_template("registro.html", tema=tema)
            if not cod_est:
                flash("Debes ingresar tu codigo de estudiante (codEst).", "error")
                return render_template("registro.html", tema=tema)
            if not foto or foto.filename == "":
                flash("Para tarifa Universitaria debes subir tu fotografia de estudiante.", "error")
                return render_template("registro.html", tema=tema)

        foto_guardada = "default.png"
        if foto and foto.filename != "":
            if not allowed_file(foto.filename):
                flash("Formato de imagen no permitido. Usa PNG, JPG, JPEG o WEBP.", "error")
                return render_template("registro.html", tema=tema)
            nombre_seguro = secure_filename(foto.filename)
            foto_guardada = f"{int(datetime.now().timestamp())}_{nombre_seguro}"
            foto.save(os.path.join(app.config["UPLOAD_FOLDER"], foto_guardada))

        conn = get_db()
        try:
            conn.execute("""
                INSERT INTO usuarios (nombre, email, password_hash, rol, categoria, rude, cod_est, foto_ref, creado_en)
                VALUES (?, ?, ?, 'pasajero', ?, ?, ?, ?, ?)
            """, (
                nombre, email, generate_password_hash(password),
                categoria, rude, cod_est, foto_guardada,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            conn.commit()
            flash("Cuenta registrada con exito. Ahora inicia sesion.", "ok")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Ese correo ya esta registrado en RUTABOL-SCZ.", "error")
        finally:
            conn.close()

    return render_template("registro.html", tema=tema)


@app.route("/")
@login_required
def index():
    tema = request.cookies.get("tema_rutabol", "claro")
    try:
        user_lat = float(request.cookies.get("user_lat", "-17.7833"))
        user_lon = float(request.cookies.get("user_lon", "-63.1821"))
    except ValueError:
        user_lat, user_lon = -17.7833, -63.1821

    conn = get_db()
    unidades_raw = conn.execute("SELECT * FROM unidades ORDER BY linea, numero_interno").fetchall()
    boletos = conn.execute("""
        SELECT b.*, u.linea, u.numero_interno, u.placa, usr.nombre AS pasajero
        FROM boletos b
        JOIN unidades u ON b.unidad_id = u.id
        JOIN usuarios usr ON b.usuario_id = usr.id
        ORDER BY b.id DESC LIMIT 15
    """).fetchall()
    conn.close()

    unidades = []
    for u in unidades_raw:
        dist = round(haversine_km(user_lat, user_lon, u["lat"], u["lon"]), 2)
        item = dict(u)
        item["distancia_km"] = dist
        item["en_radio"] = dist <= 5.0
        unidades.append(item)

    categoria = session.get("categoria", "general")
    tarifa_usuario = TARIFAS.get(categoria, 2.50)

    return render_template(
        "index.html",
        tema=tema,
        unidades=unidades,
        boletos=boletos,
        tarifa_usuario=tarifa_usuario,
        user_lat=user_lat,
        user_lon=user_lon
    )


@app.route("/ubicacion", methods=["POST"])
@login_required
def actualizar_ubicacion():
    try:
        lat = float(request.form.get("lat", "-17.7833"))
        lon = float(request.form.get("lon", "-63.1821"))
    except ValueError:
        flash("Coordenadas invalidas.", "error")
        return redirect(url_for("index"))

    resp = make_response(redirect(url_for("index")))
    resp.set_cookie("user_lat", str(lat), max_age=7 * 24 * 3600)
    resp.set_cookie("user_lon", str(lon), max_age=7 * 24 * 3600)
    flash(f"Ubicacion actualizada ({lat:.4f}, {lon:.4f}). Filtrando micros en radio de 5 km.", "ok")
    return resp


@app.route("/tema/<nuevo_tema>")
@login_required
def cambiar_tema(nuevo_tema):
    if nuevo_tema not in ("claro", "oscuro"):
        nuevo_tema = "claro"
    resp = make_response(redirect(url_for("index")))
    resp.set_cookie("tema_rutabol", nuevo_tema, max_age=30 * 24 * 3600)
    return resp


@app.route("/comprar", methods=["POST"])
@login_required
def comprar_boleto():
    unidad_id = request.form.get("unidad_id", type=int)
    tarjeta = request.form.get("tarjeta", "").strip()

    if len(tarjeta) != 16 or not tarjeta.isdigit():
        flash("Ingresa un numero de tarjeta valido de 16 digitos (RF-08).", "error")
        return redirect(url_for("index"))

    conn = get_db()
    unidad = conn.execute("SELECT * FROM unidades WHERE id = ?", (unidad_id,)).fetchone()
    if not unidad:
        conn.close()
        flash("Unidad no encontrada.", "error")
        return redirect(url_for("index"))

    if unidad["estado"] != "operativa":
        conn.close()
        flash("Esta unidad no esta operativa actualmente.", "error")
        return redirect(url_for("index"))

    if unidad["ocupados"] >= unidad["capacidad_max"]:
        conn.close()
        flash("Aforo completo: la unidad alcanzo su capacidad maxima.", "error")
        return redirect(url_for("index"))

    categoria = session.get("categoria", "general")
    monto = TARIFAS.get(categoria, 2.50)

    conn.execute("""
        UPDATE unidades
        SET ocupados = ocupados + 1, recaudacion = recaudacion + ?
        WHERE id = ?
    """, (monto, unidad_id))

    conn.execute("""
        INSERT INTO boletos (usuario_id, unidad_id, categoria, monto, tarjeta_ult4, tipo_emision, fecha)
        VALUES (?, ?, ?, ?, ?, 'compra', ?)
    """, (
        session["user_id"], unidad_id, categoria, monto,
        tarjeta[-4:], datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()

    flash(f"Boleto emitido en {unidad['linea']} ({unidad['numero_interno']}) por Bs {monto:.2f}.", "ok")
    return redirect(url_for("index"))


@app.route("/unidades/nueva", methods=["POST"])
@login_required
@roles_required("admin", "chofer")
def nueva_unidad():
    linea = request.form.get("linea", "").strip()
    numero_interno = request.form.get("numero_interno", "").strip()
    placa = request.form.get("placa", "").strip().upper()
    chofer_nombre = request.form.get("chofer_nombre", "").strip()
    capacidad_max = request.form.get("capacidad_max", type=int) or 20
    lat = request.form.get("lat", type=float) or -17.7833
    lon = request.form.get("lon", type=float) or -63.1821

    if not (18 <= capacidad_max <= 25):
        flash("El aforo permitido por norma SCZ debe estar entre 18 y 25 pasajeros (RF-05).", "error")
        return redirect(url_for("index"))

    if not linea or not numero_interno or not placa or not chofer_nombre:
        flash("Todos los datos de la unidad son obligatorios.", "error")
        return redirect(url_for("index"))

    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO unidades (linea, numero_interno, placa, chofer_nombre, capacidad_max, ocupados, recaudacion, lat, lon, estado)
            VALUES (?, ?, ?, ?, ?, 0, 0.0, ?, ?, 'operativa')
        """, (linea, numero_interno, placa, chofer_nombre, capacidad_max, lat, lon))
        conn.commit()
        flash(f"Unidad {linea} - {numero_interno} ({placa}) registrada.", "ok")
    except sqlite3.IntegrityError:
        flash("Ya existe una unidad con esa placa.", "error")
    finally:
        conn.close()

    return redirect(url_for("index"))


@app.route("/trasbordo", methods=["POST"])
@login_required
@roles_required("admin", "chofer")
def ejecutar_trasbordo():
    origen_id = request.form.get("origen_id", type=int)
    destino_id = request.form.get("destino_id", type=int)
    tipo = request.form.get("tipo", "relevo")

    if origen_id == destino_id:
        flash("La unidad de origen y destino deben ser distintas.", "error")
        return redirect(url_for("index"))

    conn = get_db()
    origen = conn.execute("SELECT * FROM unidades WHERE id = ?", (origen_id,)).fetchone()
    destino = conn.execute("SELECT * FROM unidades WHERE id = ?", (destino_id,)).fetchone()

    if not origen or not destino:
        conn.close()
        flash("Unidad origen o destino no valida.", "error")
        return redirect(url_for("index"))

    pasajeros = origen["ocupados"]
    if pasajeros == 0:
        conn.close()
        flash("La unidad de origen no tiene pasajeros para trasbordar.", "error")
        return redirect(url_for("index"))

    if destino["ocupados"] + pasajeros > destino["capacidad_max"]:
        conn.close()
        flash("La unidad destino no tiene espacio suficiente para recibir a todos los pasajeros.", "error")
        return redirect(url_for("index"))

    # RF-09 y RF-10: la unidad saliente conserva su recaudacion y la entrante recibe sin doble cobro
    nuevo_estado_origen = "relevo_finalizado" if tipo == "relevo" else "emergencia"
    conn.execute("UPDATE unidades SET ocupados = 0, estado = ? WHERE id = ?", (nuevo_estado_origen, origen_id))
    conn.execute("UPDATE unidades SET ocupados = ocupados + ? WHERE id = ?", (pasajeros, destino_id))
    conn.execute("""
        INSERT INTO boletos (usuario_id, unidad_id, categoria, monto, tarjeta_ult4, tipo_emision, fecha)
        VALUES (?, ?, 'trasbordo', 0.0, '0000', ?, ?)
    """, (
        session["user_id"], destino_id, f"trasbordo_{tipo}",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()

    flash(
        f"Trasbordo ({tipo.upper()}) completado: {pasajeros} pasajeros pasaron de "
        f"{origen['linea']} ({origen['numero_interno']}) a {destino['linea']} ({destino['numero_interno']}) sin doble cobro.",
        "ok"
    )
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Sesion cerrada correctamente.", "ok")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)