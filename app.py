from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = "clave_secreta_proyecto_escolar"

# CONEXION A LA BASE DE DATOS
def conectar():
    conexion = sqlite3.connect("usuarios.db")
    conexion.row_factory = sqlite3.Row
    return conexion

# CREAR TABLA AUTOMATICAMENTE
def crear_tabla():
    conexion = conectar()
    conexion.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL UNIQUE,
            correo TEXT NOT NULL UNIQUE,
            contrasena TEXT NOT NULL
        )
    """)
    conexion.commit()
    conexion.close()

# PROTEGER PAGINAS
def requiere_login(funcion):
    @wraps(funcion)
    def verificar(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("login"))
        return funcion(*args, **kwargs)
    return verificar

# PANTALLA LOGIN
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        nombre = request.form["nombre"]
        contrasena = request.form["contrasena"]

        conexion = conectar()
        usuario = conexion.execute(
            "SELECT * FROM usuarios WHERE nombre = ?",
            (nombre,)
        ).fetchone()
        conexion.close()

        if usuario and check_password_hash(
            usuario["contrasena"], contrasena
        ):
            session["usuario_id"] = usuario["id"]
            session["usuario_nombre"] = usuario["nombre"]
            return redirect(url_for("bienvenida"))

        flash("Usuario o contraseña incorrectos")

    return render_template("login.html")


# REGISTRO DE USUARIOS
@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre = request.form["nombre"].strip()
        correo = request.form["correo"].strip()
        contrasena = request.form["contrasena"]

        if not nombre or not correo or not contrasena:
            flash("Completa todos los campos")
            return redirect(url_for("registro"))

        conexion = conectar()

        try:
            clave = generate_password_hash(contrasena)

            conexion.execute(
                "INSERT INTO usuarios (nombre, correo, contrasena) VALUES (?, ?, ?)",
                (nombre, correo, clave)
            )
            conexion.commit()
            flash("Usuario agregado correctamente")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("El usuario o correo ya existe")

        finally:
            conexion.close()

    return render_template("registro.html")


# BIENVENIDA
@app.route("/bienvenida")
@requiere_login
def bienvenida():
    return render_template(
        "bienvenida.html",
        nombre=session["usuario_nombre"]
    )


# CONSULTAR USUARIOS (READ)
@app.route("/usuarios")
@requiere_login
def usuarios():
    conexion = conectar()
    lista = conexion.execute(
        "SELECT id, nombre, correo FROM usuarios ORDER BY id"
    ).fetchall()
    conexion.close()

    return render_template("usuarios.html", usuarios=lista)


# ACTUALIZAR USUARIO (UPDATE)
@app.route("/editar/<int:id>", methods=["GET", "POST"])
@requiere_login
def editar(id):
    conexion = conectar()

    usuario = conexion.execute(
        "SELECT * FROM usuarios WHERE id = ?", (id,)
    ).fetchone()

    if usuario is None:
        conexion.close()
        return "Usuario no encontrado", 404

    if request.method == "POST":
        nombre = request.form["nombre"].strip()
        correo = request.form["correo"].strip()

        if not nombre or not correo:
            conexion.close()
            flash("Completa todos los campos")
            return redirect(url_for("editar", id=id))

        try:
            conexion.execute(
                "UPDATE usuarios SET nombre = ?, correo = ? WHERE id = ?",
                (nombre, correo, id)
            )
            conexion.commit()

            if session["usuario_id"] == id:
                session["usuario_nombre"] = nombre

            flash("Usuario actualizado correctamente")
            return redirect(url_for("usuarios"))

        except sqlite3.IntegrityError:
            flash("Ese nombre o correo ya está registrado")

        finally:
            conexion.close()

        return redirect(url_for("editar", id=id))

    conexion.close()
    return render_template("editar.html", usuario=usuario)


# ELIMINAR USUARIO (DELETE)
@app.route("/eliminar/<int:id>", methods=["POST"])
@requiere_login
def eliminar(id):
    if session["usuario_id"] == id:
        flash("No puedes eliminar tu propia cuenta mientras estás conectado")
        return redirect(url_for("usuarios"))

    conexion = conectar()
    conexion.execute(
        "DELETE FROM usuarios WHERE id = ?", (id,)
    )
    conexion.commit()
    conexion.close()

    flash("Usuario eliminado correctamente")
    return redirect(url_for("usuarios"))


# CERRAR SESION
@app.route("/salir")
def salir():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    crear_tabla()
    app.run(debug=True)