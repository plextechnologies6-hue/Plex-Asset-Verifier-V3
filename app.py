import os
import csv
import io
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")

database_url = os.environ.get("DATABASE_URL", "").strip()
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url or (
    "sqlite:///" + os.path.join(BASE_DIR, "plex_v3.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "error"


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(180), nullable=False)
    email = db.Column(db.String(180), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="Field Officer")
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Client(db.Model):
    __tablename__ = "clients"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    code = db.Column(db.String(80), unique=True, nullable=True)
    contact_person = db.Column(db.String(160))
    email = db.Column(db.String(160))
    phone = db.Column(db.String(80))
    address = db.Column(db.String(300))
    notes = db.Column(db.Text)
    status = db.Column(db.String(40), default="Active")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sessions = db.relationship(
        "VerificationSession",
        back_populates="client",
        cascade="all, delete-orphan",
    )


class VerificationSession(db.Model):
    __tablename__ = "verification_sessions"
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False)
    name = db.Column(db.String(240), nullable=False)
    reference_no = db.Column(db.String(100), unique=True, nullable=True)
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    status = db.Column(db.String(40), default="Planning")
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    client = db.relationship("Client", back_populates="sessions")
    far_assets = db.relationship(
        "FARAsset", back_populates="session", cascade="all, delete-orphan"
    )
    field_assets = db.relationship(
        "FieldAsset", back_populates="session", cascade="all, delete-orphan"
    )


class FARAsset(db.Model):
    __tablename__ = "far_assets"
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(
        db.Integer, db.ForeignKey("verification_sessions.id"), nullable=False
    )
    asset_name = db.Column(db.String(250), nullable=False)
    description = db.Column(db.Text)
    tag_number = db.Column(db.String(120))
    location = db.Column(db.String(250))
    serial_number = db.Column(db.String(180))
    model = db.Column(db.String(180))
    user_name = db.Column(db.String(180))
    custodian = db.Column(db.String(180))
    source_row = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    session = db.relationship("VerificationSession", back_populates="far_assets")


class FieldAsset(db.Model):
    __tablename__ = "field_assets"
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(
        db.Integer, db.ForeignKey("verification_sessions.id"), nullable=False
    )
    asset_name = db.Column(db.String(250), nullable=False)
    description = db.Column(db.Text)
    tag_number = db.Column(db.String(120))
    location = db.Column(db.String(250))
    serial_number = db.Column(db.String(180))
    model = db.Column(db.String(180))
    user_name = db.Column(db.String(180))
    custodian = db.Column(db.String(180))
    status = db.Column(db.String(60), default="Verified")
    condition = db.Column(db.String(80), default="Good")
    remarks = db.Column(db.Text)
    verified_by = db.Column(db.String(160))
    verified_at = db.Column(db.DateTime, default=datetime.utcnow)
    photo_filename = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    session = db.relationship("VerificationSession", back_populates="field_assets")


with app.app_context():
    db.create_all()

    # Optional one-time bootstrap of the first Admin user using Render env vars.
    admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "").strip()
    if admin_email and admin_password and not User.query.filter_by(email=admin_email).first():
        admin = User(
            full_name=os.environ.get("ADMIN_NAME", "Plex Administrator"),
            email=admin_email,
            role="Admin",
            active=True,
        )
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if not current_user.active or current_user.role not in roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def norm(value):
    return "".join((value or "").lower().split())


def field_match_status(far_asset, field_assets):
    tag = norm(far_asset.tag_number)
    serial = norm(far_asset.serial_number)

    if tag:
        for asset in field_assets:
            if norm(asset.tag_number) == tag:
                return asset, "Tag Number"

    if serial:
        for asset in field_assets:
            if norm(asset.serial_number) == serial:
                return asset, "Serial Number"

    key = (norm(far_asset.asset_name), norm(far_asset.location))
    candidates = [
        a for a in field_assets
        if (norm(a.asset_name), norm(a.location)) == key
    ]
    if len(candidates) == 1:
        return candidates[0], "Asset Name + Location"

    return None, ""


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user and user.active and user.check_password(password):
            login_user(user, remember=True)
            next_url = request.args.get("next")
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("dashboard"))

        flash("Invalid email/password or inactive account.", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.errorhandler(403)
def forbidden(_):
    return render_template("403.html"), 403


@app.route("/")
def landing():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


@app.route("/dashboard")
@login_required
def dashboard():
    clients = Client.query.count()
    sessions = VerificationSession.query.count()
    field_count = FieldAsset.query.count()
    far_count = FARAsset.query.count()
    verified = FieldAsset.query.filter_by(status="Verified").count()
    not_found = FieldAsset.query.filter_by(status="Not Found").count()
    untagged = FieldAsset.query.filter_by(status="Untagged").count()
    active_sessions = VerificationSession.query.filter(
        VerificationSession.status.in_(["Planning", "Active"])
    ).count()

    recent_sessions = VerificationSession.query.order_by(
        VerificationSession.created_at.desc()
    ).limit(8).all()

    return render_template(
        "dashboard.html",
        clients=clients,
        sessions=sessions,
        field_count=field_count,
        far_count=far_count,
        verified=verified,
        not_found=not_found,
        untagged=untagged,
        active_sessions=active_sessions,
        recent_sessions=recent_sessions,
    )


@app.route("/users")
@role_required("Admin")
def users():
    rows = User.query.order_by(User.created_at.desc()).all()
    return render_template("users.html", users=rows)


@app.route("/users/new", methods=["GET", "POST"])
@role_required("Admin")
def new_user():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "Field Officer")
        active = request.form.get("active") == "on"

        if not full_name or not email or not password:
            flash("Full name, email and password are required.", "error")
            return render_template("user_form.html", title="New User", user=request.form)

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("user_form.html", title="New User", user=request.form)

        if User.query.filter_by(email=email).first():
            flash("A user with that email already exists.", "error")
            return render_template("user_form.html", title="New User", user=request.form)

        if role not in ["Admin", "Supervisor", "Field Officer", "Client Viewer"]:
            flash("Invalid role.", "error")
            return render_template("user_form.html", title="New User", user=request.form)

        user = User(
            full_name=full_name,
            email=email,
            role=role,
            active=active,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("User created successfully.", "success")
        return redirect(url_for("users"))

    return render_template("user_form.html", title="New User", user={})


@app.route("/users/<int:user_id>/toggle", methods=["POST"])
@role_required("Admin")
def toggle_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)

    if user.id == current_user.id:
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for("users"))

    user.active = not user.active
    db.session.commit()
    flash(
        f"{user.full_name} is now {'active' if user.active else 'inactive'}.",
        "success",
    )
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/reset-password", methods=["POST"])
@role_required("Admin")
def reset_password(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)

    new_password = request.form.get("new_password", "")
    if len(new_password) < 8:
        flash("New password must be at least 8 characters.", "error")
        return redirect(url_for("users"))

    user.set_password(new_password)
    db.session.commit()
    flash(f"Password reset for {user.full_name}.", "success")
    return redirect(url_for("users"))


@app.route("/clients")
@login_required
def clients():
    rows = Client.query.order_by(Client.name.asc()).all()
    return render_template("clients.html", clients=rows)


@app.route("/clients/new", methods=["GET", "POST"])
@role_required("Admin", "Supervisor")
def new_client():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("Client name is required.", "error")
            return render_template("client_form.html", title="New Client", client={})

        code = request.form.get("code", "").strip() or None
        if code and Client.query.filter_by(code=code).first():
            flash("Client code already exists.", "error")
            return render_template("client_form.html", title="New Client", client=request.form)

        client = Client(
            name=name,
            code=code,
            contact_person=request.form.get("contact_person", "").strip(),
            email=request.form.get("email", "").strip(),
            phone=request.form.get("phone", "").strip(),
            address=request.form.get("address", "").strip(),
            notes=request.form.get("notes", "").strip(),
            status=request.form.get("status", "Active"),
        )
        db.session.add(client)
        db.session.commit()

        flash("Client created successfully.", "success")
        return redirect(url_for("clients"))

    return render_template("client_form.html", title="New Client", client={})


@app.route("/clients/<int:client_id>")
@login_required
def client_detail(client_id):
    client = db.session.get(Client, client_id)
    if not client:
        abort(404)

    sessions = VerificationSession.query.filter_by(
        client_id=client_id
    ).order_by(VerificationSession.created_at.desc()).all()

    return render_template("client_detail.html", client=client, sessions=sessions)


@app.route("/sessions/new", methods=["GET", "POST"])
@role_required("Admin", "Supervisor")
def new_session():
    client_id = request.args.get("client_id", type=int)
    clients_list = Client.query.order_by(Client.name.asc()).all()

    if request.method == "POST":
        client_id = request.form.get("client_id", type=int)
        client = db.session.get(Client, client_id) if client_id else None

        if not client:
            flash("Please select a valid client.", "error")
            return render_template("session_form.html", clients=clients_list, session={})

        name = request.form.get("name", "").strip()
        if not name:
            flash("Session name is required.", "error")
            return render_template(
                "session_form.html", clients=clients_list, session=request.form
            )

        reference_no = request.form.get("reference_no", "").strip() or None
        if reference_no and VerificationSession.query.filter_by(
            reference_no=reference_no
        ).first():
            flash("Reference number already exists.", "error")
            return render_template(
                "session_form.html", clients=clients_list, session=request.form
            )

        from datetime import date

        start_date = request.form.get("start_date") or None
        end_date = request.form.get("end_date") or None

        session = VerificationSession(
            client_id=client_id,
            name=name,
            reference_no=reference_no,
            start_date=date.fromisoformat(start_date) if start_date else None,
            end_date=date.fromisoformat(end_date) if end_date else None,
            status=request.form.get("status", "Planning"),
            notes=request.form.get("notes", "").strip(),
        )

        db.session.add(session)
        db.session.commit()

        flash("Verification session created.", "success")
        return redirect(url_for("session_detail", session_id=session.id))

    return render_template(
        "session_form.html",
        clients=clients_list,
        session={"client_id": client_id} if client_id else {},
    )


@app.route("/sessions/<int:session_id>")
@login_required
def session_detail(session_id):
    session = db.session.get(VerificationSession, session_id)
    if not session:
        abort(404)

    far_count = FARAsset.query.filter_by(session_id=session_id).count()
    field_count = FieldAsset.query.filter_by(session_id=session_id).count()
    verified = FieldAsset.query.filter_by(
        session_id=session_id, status="Verified"
    ).count()
    not_found = FieldAsset.query.filter_by(
        session_id=session_id, status="Not Found"
    ).count()
    untagged = FieldAsset.query.filter_by(
        session_id=session_id, status="Untagged"
    ).count()

    return render_template(
        "session_detail.html",
        session=session,
        far_count=far_count,
        field_count=field_count,
        verified=verified,
        not_found=not_found,
        untagged=untagged,
    )


@app.route("/sessions/<int:session_id>/assets")
@login_required
def session_assets(session_id):
    session = db.session.get(VerificationSession, session_id)
    if not session:
        abort(404)

    q = request.args.get("q", "").strip()
    query = FieldAsset.query.filter_by(session_id=session_id)

    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                FieldAsset.asset_name.ilike(like),
                FieldAsset.tag_number.ilike(like),
                FieldAsset.serial_number.ilike(like),
                FieldAsset.location.ilike(like),
                FieldAsset.custodian.ilike(like),
            )
        )

    assets = query.order_by(FieldAsset.id.desc()).all()
    return render_template(
        "session_assets.html", session=session, assets=assets, q=q
    )


@app.route("/sessions/<int:session_id>/assets/new", methods=["GET", "POST"])
@role_required("Admin", "Supervisor", "Field Officer")
def new_field_asset(session_id):
    session = db.session.get(VerificationSession, session_id)
    if not session:
        abort(404)

    if request.method == "POST":
        asset_name = request.form.get("asset_name", "").strip()

        if not asset_name:
            flash("Asset name is required.", "error")
            return render_template(
                "asset_form.html",
                session=session,
                asset=request.form,
                title="Capture Asset",
            )

        asset = FieldAsset(
            session_id=session_id,
            asset_name=asset_name,
            description=request.form.get("description", "").strip(),
            tag_number=request.form.get("tag_number", "").strip(),
            location=request.form.get("location", "").strip(),
            serial_number=request.form.get("serial_number", "").strip(),
            model=request.form.get("model", "").strip(),
            user_name=request.form.get("user_name", "").strip(),
            custodian=request.form.get("custodian", "").strip(),
            status=request.form.get("status", "Verified"),
            condition=request.form.get("condition", "Good"),
            remarks=request.form.get("remarks", "").strip(),
            verified_by=request.form.get("verified_by", "").strip()
            or current_user.full_name,
        )

        db.session.add(asset)
        db.session.commit()

        flash("Field asset captured.", "success")
        return redirect(url_for("session_assets", session_id=session_id))

    return render_template(
        "asset_form.html", session=session, asset={}, title="Capture Asset"
    )


@app.route("/sessions/<int:session_id>/far/import", methods=["GET", "POST"])
@role_required("Admin", "Supervisor")
def import_far(session_id):
    session = db.session.get(VerificationSession, session_id)
    if not session:
        abort(404)

    if request.method == "POST":
        file = request.files.get("file")
        if not file or not file.filename.lower().endswith(".csv"):
            flash("Please upload a CSV file for this release.", "error")
            return redirect(url_for("import_far", session_id=session_id))

        if request.form.get("replace_existing") == "yes":
            FARAsset.query.filter_by(session_id=session_id).delete()

        text = file.read().decode("utf-8-sig", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        imported = 0

        aliases = {
            "asset name": ["asset name", "asset_name", "asset"],
            "description": ["description", "asset description"],
            "tag number": ["tag number", "tag_number", "asset tag", "tag"],
            "location": ["location", "current location"],
            "serial number": [
                "serial number",
                "serial_number",
                "serial",
                "serial no",
            ],
            "model": ["model", "model number"],
            "user": ["user", "user name", "user_name"],
            "custodian": ["custodian"],
        }

        def pick(row, key):
            normalized = {
                str(k).strip().lower(): (v or "").strip()
                for k, v in row.items()
                if k
            }
            for alias in aliases[key]:
                if alias in normalized:
                    return normalized[alias]
            return ""

        for row_no, row in enumerate(reader, start=2):
            name = pick(row, "asset name")
            if not name:
                continue

            db.session.add(
                FARAsset(
                    session_id=session_id,
                    asset_name=name,
                    description=pick(row, "description"),
                    tag_number=pick(row, "tag number"),
                    location=pick(row, "location"),
                    serial_number=pick(row, "serial number"),
                    model=pick(row, "model"),
                    user_name=pick(row, "user"),
                    custodian=pick(row, "custodian"),
                    source_row=row_no,
                )
            )
            imported += 1

        db.session.commit()
        flash(
            f"{imported} FAR records imported into {session.name}.",
            "success",
        )
        return redirect(url_for("session_detail", session_id=session_id))

    return render_template("import_far.html", session=session)


@app.route("/sessions/<int:session_id>/reconcile")
@login_required
def reconcile(session_id):
    session = db.session.get(VerificationSession, session_id)
    if not session:
        abort(404)

    far_assets = FARAsset.query.filter_by(
        session_id=session_id
    ).order_by(FARAsset.id).all()
    field_assets = FieldAsset.query.filter_by(
        session_id=session_id
    ).order_by(FieldAsset.id).all()

    results = []
    used = set()

    for far in far_assets:
        match, basis = field_match_status(far, field_assets)

        if match:
            used.add(match.id)
            differences = []

            for field in [
                "asset_name",
                "description",
                "tag_number",
                "location",
                "serial_number",
                "model",
                "user_name",
                "custodian",
            ]:
                if norm(getattr(far, field)) != norm(getattr(match, field)):
                    differences.append(field)

            status = "Matched - Differences" if differences else "Matched"
            results.append((far, match, basis, status, differences))
        else:
            results.append((far, None, "", "Not Found in Field", []))

    field_only = [a for a in field_assets if a.id not in used]
    matched = sum(1 for result in results if result[3].startswith("Matched"))
    differences = sum(
        1 for result in results if result[3] == "Matched - Differences"
    )
    not_found = sum(
        1 for result in results if result[3] == "Not Found in Field"
    )

    return render_template(
        "reconcile.html",
        session=session,
        results=results,
        field_only=field_only,
        stats={
            "far": len(far_assets),
            "matched": matched,
            "differences": differences,
            "not_found": not_found,
            "field_only": len(field_only),
        },
    )


@app.route("/sessions/<int:session_id>/export")
@role_required("Admin", "Supervisor")
def export_field(session_id):
    session = db.session.get(VerificationSession, session_id)
    if not session:
        abort(404)

    rows = FieldAsset.query.filter_by(session_id=session_id).order_by(
        FieldAsset.id
    ).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "ID",
            "Asset Name",
            "Description",
            "Tag Number",
            "Location",
            "Serial Number",
            "Model",
            "User",
            "Custodian",
            "Status",
            "Condition",
            "Remarks",
            "Verified By",
            "Verified At",
        ]
    )

    for asset in rows:
        writer.writerow(
            [
                asset.id,
                asset.asset_name,
                asset.description,
                asset.tag_number,
                asset.location,
                asset.serial_number,
                asset.model,
                asset.user_name,
                asset.custodian,
                asset.status,
                asset.condition,
                asset.remarks,
                asset.verified_by,
                asset.verified_at.isoformat() if asset.verified_at else "",
            ]
        )

    data = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    return send_file(
        data,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"Field_Register_{session.reference_no or session.id}.csv",
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=True,
    )
