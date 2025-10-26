from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename 
from datetime import datetime
import os 
import string
import random

# --- Configuración de la Aplicación ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'una_clave_secreta_fuerte_aqui_para_el_login' 

# CONFIGURACIÓN DE ARCHIVOS
UPLOAD_FOLDER = 'static/fotos_paquetes' # Carpeta donde se guardarán las fotos
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'} 

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Asegúrate de que la carpeta exista
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 
login_manager.login_message_category = 'warning'

# --- Estados Predefinidos ---
ESTADOS_PREDEFINIDOS = [
    "Pedido creado", 
    "Paquete enviado", 
    "Su paquete llegó a nuestro país (Perú)", 
    "En aduana Perú", 
    "Liberado de aduana", 
    "Recepcionado por el transportista local", 
    "En nuestro almacén", 
    "Salió a reparto", 
    "Entregado"
]

# --- Definición de Modelos (Base de Datos) ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Paquete(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    codigo_seguimiento = db.Column(db.String(80), unique=True, nullable=False) 
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)
    estados = db.relationship('EstadoSeguimiento', backref='paquete', lazy=True, cascade="all, delete-orphan") 

    def __repr__(self):
        return f'<Paquete {self.codigo_seguimiento}>'

class EstadoSeguimiento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    paquete_id = db.Column(db.Integer, db.ForeignKey('paquete.id'), nullable=False)
    fecha_hora = db.Column(db.DateTime, default=datetime.utcnow)
    ubicacion = db.Column(db.String(100), nullable=True)
    descripcion = db.Column(db.String(200), nullable=False)
    foto_url = db.Column(db.String(250), nullable=True) 

    def __repr__(self):
        return f'<Estado {self.descripcion}>'

# --- Funciones de Utilidad ---

def create_db():
    with app.app_context():
        db.create_all()

def generate_custom_code(paquete_id):
    prefix = "IDFYOHE" 
    return f"{prefix}{str(paquete_id).zfill(5)}"

def allowed_file(filename):
    """Verifica si la extensión del archivo es permitida."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def handle_file_upload(file_key='foto'):
    """Maneja la subida de un archivo de foto y retorna el path relativo."""
    if file_key in request.files:
        foto = request.files[file_key]
        if foto.filename != '' and allowed_file(foto.filename):
            filename = secure_filename(foto.filename)
            unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            foto.save(file_path)
            # Retorna el path relativo
            return f"/{app.config['UPLOAD_FOLDER']}/{unique_filename}"
    return None

# --- RUTAS DE SEGURIDAD (LOGIN/REGISTRO) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('listar_paquetes'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('listar_paquetes')) 
        else:
            flash('Usuario o contraseña inválidos.', 'danger')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('El nombre de usuario ya existe. Intenta iniciar sesión.', 'danger')
            return redirect(url_for('login'))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Cuenta creada con éxito. Por favor, inicia sesión.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada correctamente.', 'info')
    # CAMBIO CRÍTICO: Redirige a la página de login
    return redirect(url_for('login')) 

# --- RUTAS DEL PANEL DE ADMINISTRACIÓN (PROTEGIDAS) ---

@app.route('/admin')
@login_required 
def admin_index():
    return redirect(url_for('listar_paquetes'))

# 1. CREAR NUEVO RASTREO
@app.route('/admin/crear', methods=['GET', 'POST'])
@login_required
def crear_paquete():
    
    if request.method == 'POST':
        
        # 1. Manejo de Subida de Archivo
        foto_url = handle_file_upload()
        
        # 2. Lógica de creación del paquete (Resuelve IntegrityError)
        nuevo_paquete = Paquete(codigo_seguimiento='TEMP_CODE')
        db.session.add(nuevo_paquete)
        db.session.commit() 
        
        codigo_generado = generate_custom_code(nuevo_paquete.id)
        nuevo_paquete.codigo_seguimiento = codigo_generado 

        # 3. Obtener datos del formulario
        descripcion = request.form.get('descripcion') 
        ubicacion = request.form.get('ubicacion')

        # 4. Crear el estado inicial
        nuevo_estado = EstadoSeguimiento(
            paquete_id=nuevo_paquete.id,
            descripcion=descripcion,
            ubicacion=ubicacion,
            foto_url=foto_url 
        )
        
        db.session.add(nuevo_estado)
        db.session.commit() 
        
        flash(f'¡Rastreo creado! Código: {codigo_generado}', 'success')
        return redirect(url_for('actualizar_paquete', tracking_id=nuevo_paquete.id))

    return render_template('admin_crear.html', estados_disponibles=ESTADOS_PREDEFINIDOS) 

# 2. LISTAR PAQUETES
@app.route('/admin/paquetes', methods=['GET'])
@login_required
def listar_paquetes():
    busqueda = request.args.get('q', '')
    if busqueda:
        paquetes = Paquete.query.filter(
            Paquete.codigo_seguimiento.like(f'%{busqueda}%')
        ).order_by(Paquete.fecha_creacion.desc()).all()
    else:
        paquetes = Paquete.query.order_by(Paquete.fecha_creacion.desc()).all()
        
    return render_template('admin_listar.html', paquetes=paquetes, busqueda=busqueda)

# 3. ACTUALIZAR PAQUETE
@app.route('/admin/actualizar/<int:tracking_id>', methods=['GET', 'POST'])
@login_required
def actualizar_paquete(tracking_id):
    paquete = Paquete.query.get_or_404(tracking_id)
    
    if request.method == 'POST':
        
        # 1. Manejo de Subida de Archivo
        foto_url = handle_file_upload()

        # 2. Añadir un nuevo estado
        descripcion = request.form.get('descripcion')
        ubicacion = request.form.get('ubicacion')

        nuevo_estado = EstadoSeguimiento(
            paquete_id=paquete.id,
            descripcion=descripcion,
            ubicacion=ubicacion,
            foto_url=foto_url
        )
        db.session.add(nuevo_estado)
        db.session.commit()
        
        flash('Nuevo estado de seguimiento añadido con éxito.', 'success')
        return redirect(url_for('actualizar_paquete', tracking_id=paquete.id))

    # Obtener el historial de estados
    estados = EstadoSeguimiento.query.filter_by(paquete_id=paquete.id).order_by(EstadoSeguimiento.fecha_hora.desc()).all()
    
    return render_template('admin_actualizar.html', paquete=paquete, estados=estados, estados_disponibles=ESTADOS_PREDEFINIDOS)

# --- RUTAS DE LA INTERFAZ PÚBLICA (CLIENTE) ---

@app.route('/', methods=['GET'])
def index():
    return render_template('tracking.html', tracking_data=None)

@app.route('/track', methods=['POST'])
def track_package():
    codigo = request.form.get('codigo_busqueda')
    
    paquete = Paquete.query.filter_by(codigo_seguimiento=codigo).first()
    
    tracking_data = None
    if paquete:
        estados = EstadoSeguimiento.query.filter_by(paquete_id=paquete.id).order_by(EstadoSeguimiento.fecha_hora.desc()).all()
        
        tracking_data = {
            'codigo': paquete.codigo_seguimiento,
            'estados': [{
                'fecha_hora': estado.fecha_hora.strftime('%Y-%m-%d %H:%M:%S'),
                'descripcion': estado.descripcion,
                'ubicacion': estado.ubicacion if estado.ubicacion else 'N/A',
                'foto_url': estado.foto_url
            } for estado in estados]
        }
    else:
        flash(f'Código de seguimiento "{codigo}" no encontrado.', 'danger')
        
    return render_template('tracking.html', tracking_data=tracking_data)

if __name__ == '__main__':
    create_db() 
    
    with app.app_context():
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin')
            admin_user.set_password('1234') 
            db.session.add(admin_user)
            db.session.commit()
            print("¡Usuario admin (admin/1234) creado para empezar! ¡Cámbialo!")
            
    app.run(debug=True)