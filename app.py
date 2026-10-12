import os
import subprocess
from datetime import datetime
from flask import Flask, jsonify, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

# --- GÜVENLİK VE VERİTABANI AYARLARI ---
app.config['SECRET_KEY'] = 'omnicloud-super-secret-key-2026-secure'
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(BASE_DIR, 'omnicloud_users.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["300 per day", "100 per hour"],
    storage_uri="memory://"
)
ph = PasswordHasher()

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Uygulamaya erişmek için lütfen önce giriş yapın."
login_manager.login_message_category = "danger"

# --- VIRTUALBOX AYARLARI ---
VBOX_PATH = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
VM_NAME = "omni"


# --- KULLANICI MODELİ ---
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(25), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    membership_plan = db.Column(db.String(50), default='Başlangıç', nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = ph.hash(password)

    def check_password(self, password):
        try:
            return ph.verify(self.password_hash, password)
        except VerifyMismatchError:
            return False

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# --- SAYFA ROTALARI ---

@app.route("/")
def index():
    return render_template("home.html")

@app.route("/planlar")
def plans():
    return render_template("plans.html")

@app.route("/odeme", methods=["GET", "POST"])
@login_required
def checkout():
    plan = request.args.get('plan', 'Ultimate')
    
    # Fiyat tablosu
    fiyatlar = {
        'Başlangıç': 0,
        'Ultimate': 199,
        'Kurumsal': 399
    }
    tutar = fiyatlar.get(plan, 199)

    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "pay":
            # Başarılı ödeme simülasyonu: kullanıcının planını güncelle
            current_user.membership_plan = plan
            db.session.commit()
            flash(f"Ödemeniz başarıyla tamamlandı! {plan} paketiniz aktif edildi.", "success")
            return redirect(url_for('my_app'))
        else:
            # Ödeme başarısız / iptal
            flash("Ödeme yapılamadı veya işlem kullanıcı tarafından iptal edildi.", "danger")
            return redirect(url_for('index'))

    return render_template("checkout.html", plan=plan, tutar=tutar)

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def register():
    # Kullanıcı zaten giriş yapmışsa kayıt sayfasını gösterme, paketler sayfasına gönder
    if current_user.is_authenticated:
        return redirect(url_for('plans'))

    plan = request.args.get('plan', 'Ultimate')
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password")
        password_confirm = request.form.get("password_confirm")
        selected_plan = request.form.get("plan", "Ultimate")

        if password != password_confirm:
            flash("Girdiğiniz şifreler birbiriyle eşleşmiyor!", "danger")
            return redirect(url_for('register', plan=selected_plan))

        if len(password) < 8:
            flash("Şifre en az 8 karakter olmalıdır!", "danger")
            return redirect(url_for('register', plan=selected_plan))

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash("Bu kullanıcı adı veya e-posta zaten kullanımda.", "danger")
            return redirect(url_for('register', plan=selected_plan))

        new_user = User(
            username=username,
            email=email,
            phone=phone if phone else None,
            membership_plan=selected_plan
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        flash("Hesabınız oluşturuldu, hoş geldiniz!", "success")
        return redirect(url_for('my_app'))

    return render_template("register.html", plan=plan)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        identifier = request.form.get("login_identifier", "").strip()
        password = request.form.get("password")

        user = User.query.filter(
            (User.email == identifier.lower()) | 
            (User.username == identifier) | 
            (User.phone == identifier)
        ).first()

        if user and user.check_password(password):
            if not user.is_active:
                flash("Hesabınız askıya alınmıştır.", "danger")
                return redirect(url_for('login'))

            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user)

            next_page = request.args.get("next")
            if not next_page or not next_page.startswith('/'):
                next_page = url_for("my_app")
            return redirect(next_page)
        else:
            flash("Hatalı kullanıcı bilgisi veya şifre!", "danger")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Güvenli bir şekilde çıkış yapıldı.", "success")
    return redirect(url_for("index"))

@app.route("/profil")
@login_required
def profile():
    return render_template("profile.html")

@app.route("/app")
@login_required
def my_app():
    return render_template("index.html")


# --- VIRTUALBOX YÖNETİM API'LERİ ---

@app.route("/api/vm/status", methods=["GET"])
@login_required
def vm_status():
    try:
        check_cmd = [VBOX_PATH, "showvminfo", VM_NAME, "--machinereadable"]
        output = subprocess.check_output(
            check_cmd, stderr=subprocess.STDOUT, text=True
        )
        is_running = 'VMState="running"' in output
        return jsonify({"running": is_running})
    except Exception as e:
        return jsonify({"running": False, "error": str(e)})


@app.route("/api/vm/start", methods=["POST"])
@csrf.exempt
@login_required
def start_vm():
    try:
        check_cmd = [VBOX_PATH, "showvminfo", VM_NAME, "--machinereadable"]
        output = subprocess.check_output(
            check_cmd, stderr=subprocess.STDOUT, text=True
        )
        if 'VMState="running"' in output:
            return jsonify({"success": True, "message": "OmniCloud zaten çalışır durumda."})

        start_cmd = [VBOX_PATH, "startvm", VM_NAME, "--type", "headless"]
        subprocess.Popen(start_cmd)
        return jsonify({"success": True, "message": "OmniCloud Masaüstü başlatılıyor..."})
    except subprocess.CalledProcessError as e:
        return jsonify({"success": False, "error": f"VBox Hatası: {e.output.strip()}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/vm/stop", methods=["POST"])
@csrf.exempt
@login_required
def stop_vm():
    stop_cmd = [VBOX_PATH, "controlvm", VM_NAME, "poweroff"]
    try:
        subprocess.check_output(stop_cmd, stderr=subprocess.STDOUT, text=True)
        return jsonify({"success": True, "message": "OmniCloud kapatıldı."})
    except Exception:
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", "VBoxHeadless.exe"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return jsonify({"success": True, "message": "OmniCloud işlemi sonlandırıldı."})
        except Exception as kill_err:
            return jsonify({"success": False, "error": str(kill_err)})


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)