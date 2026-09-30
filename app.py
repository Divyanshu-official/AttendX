from flask import Flask, render_template, request, redirect, url_for, session
from functools import wraps
import csv
import os
from dotenv import load_dotenv

load_dotenv()
import time
import json
import hmac
import hashlib
import base64
from datetime import datetime


app = Flask(__name__)


# ============================================================
# LOCAL NETWORK / CORS HEADERS
# ============================================================

@app.after_request
def add_local_network_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Private-Network"] = "true"
    return response


# ============================================================
# APP CONFIGURATION
# ============================================================

app.secret_key = os.getenv("ATTENDX_SECRET_KEY")


# ============================================================
# TEACHER LOGIN
# ============================================================

TEACHER_USERNAME = os.getenv("ATTENDX_TEACHER_USERNAME")
TEACHER_PASSWORD = os.getenv("ATTENDX_TEACHER_PASSWORD")


# ============================================================
# LOCAL VERIFICATION SECURITY
# ============================================================

VERIFICATION_SECRET = os.getenv(
    "ATTENDX_VERIFICATION_SECRET",
    "attendx-local-verification-secret-change-this"
)

VERIFICATION_TOKEN_LIFETIME = 60


# ============================================================
# ATTENDANCE / REGISTRATION STATUS
# ============================================================

attendance_status = False
registration_allowed = False


# ============================================================
# TEACHER HOTSPOT CONFIGURATION
# ============================================================

TEACHER_IP = "10.24.206.20"

ALLOWED_IP_PREFIX = ".".join(
    TEACHER_IP.split(".")[:-1]
) + "."


# ============================================================
# TOKEN HELPER FUNCTIONS
# ============================================================

def create_verification_token(student_ip):
    """
    Create a short-lived signed verification token.
    """

    current_time = int(time.time())
    expires_at = (
        current_time
        + VERIFICATION_TOKEN_LIFETIME
    )

    payload = {
        "ip": student_ip,
        "iat": current_time,
        "exp": expires_at,
        "service": "AttendX"
    }

    payload_json = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True
    )

    payload_encoded = base64.urlsafe_b64encode(
        payload_json.encode("utf-8")
    ).decode("utf-8").rstrip("=")

    signature = hmac.new(
        VERIFICATION_SECRET.encode("utf-8"),
        payload_encoded.encode("utf-8"),
        hashlib.sha256
    ).digest()

    signature_encoded = base64.urlsafe_b64encode(
        signature
    ).decode("utf-8").rstrip("=")

    token = (
        payload_encoded
        + "."
        + signature_encoded
    )

    return token, expires_at


def verify_verification_token(token):
    """
    Verify the temporary signed AttendX verification token.

    Returns the decoded payload when valid.
    Returns None when the token is invalid or expired.
    """

    try:
        if not token or "." not in token:
            return None

        parts = token.split(".", 1)

        if len(parts) != 2:
            return None

        payload_encoded, signature_encoded = parts

        if not payload_encoded or not signature_encoded:
            return None

        expected_signature = hmac.new(
            VERIFICATION_SECRET.encode("utf-8"),
            payload_encoded.encode("utf-8"),
            hashlib.sha256
        ).digest()

        expected_signature_encoded = (
            base64.urlsafe_b64encode(
                expected_signature
            )
            .decode("utf-8")
            .rstrip("=")
        )

        if not hmac.compare_digest(
            signature_encoded,
            expected_signature_encoded
        ):
            print(
                "[VERIFICATION] ❌ Invalid token signature."
            )
            return None

        padding = "=" * ((-len(payload_encoded)) % 4)

        payload_json = base64.urlsafe_b64decode(
            payload_encoded + padding
        ).decode("utf-8")

        payload = json.loads(payload_json)

        if not isinstance(payload, dict):
            return None

        if payload.get("service") != "AttendX":
            print(
                "[VERIFICATION] ❌ Invalid token service."
            )
            return None

        if "ip" not in payload or "iat" not in payload or "exp" not in payload:
            return None

        current_time = int(time.time())
        expires_at = int(payload["exp"])

        if current_time >= expires_at:
            print(
                "[VERIFICATION] ❌ Token expired."
            )
            return None

        print(
            "[VERIFICATION] ✅ Token verified successfully."
        )

        return payload

    except Exception as error:
        print(
            f"[ERROR] Token verification failed: {error}"
        )
        return None


# ============================================================
# TEACHER AUTHENTICATION DECORATOR
# ============================================================

def teacher_required(view):

    @wraps(view)
    def wrapped_view(*args, **kwargs):

        if not session.get(
            "teacher_authenticated"
        ):

            return redirect(
                url_for(
                    "teacher_login",
                    next=request.path
                )
            )

        return view(*args, **kwargs)

    return wrapped_view


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ============================================================
# TEACHER LOGIN
# ============================================================

@app.route(
    "/teacher/login",
    methods=["GET", "POST"]
)
def teacher_login():

    message = ""

    next_url = (
        request.args.get("next")
        or request.form.get("next")
        or url_for("teacher_page")
    )

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if (
            username == TEACHER_USERNAME
            and password == TEACHER_PASSWORD
        ):

            session[
                "teacher_authenticated"
            ] = True

            return redirect(
                next_url
                if next_url.startswith("/")
                else url_for("teacher_page")
            )

        message = (
            "❌ Invalid teacher username or password."
        )

    return render_template(
        "teacher_login.html",
        message=message,
        next_url=next_url
    )


# ============================================================
# TEACHER LOGOUT
# ============================================================

@app.route(
    "/teacher/logout",
    methods=["POST"]
)
def teacher_logout():

    session.pop(
        "teacher_authenticated",
        None
    )

    return redirect(
        url_for("home")
    )


# ============================================================
# TEACHER DASHBOARD
# ============================================================

@app.route("/teacher")
@teacher_required
def teacher_page():

    status_text = (
        "ON"
        if attendance_status
        else "OFF"
    )

    return render_template(
        "teacher.html",
        status=status_text,
        registration_status=registration_allowed,
    )


# ============================================================
# TOGGLE ATTENDANCE
# ============================================================

@app.route(
    "/toggle_attendance",
    methods=["POST"]
)
@teacher_required
def toggle_attendance():

    global attendance_status

    attendance_status = not attendance_status

    return redirect(
        url_for("teacher_page")
    )


# ============================================================
# TOGGLE REGISTRATION
# ============================================================

@app.route(
    "/toggle_registration",
    methods=["POST"]
)
@teacher_required
def toggle_registration():

    global registration_allowed

    registration_allowed = not registration_allowed

    return redirect(
        url_for("teacher_page")
    )


# ============================================================
# STUDENT REGISTRATION
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register_student():

    global registration_allowed

    message = ""

    if request.method == "POST":

        ip_address = request.remote_addr

        print(
            f"[DEBUG] Registration IP address: "
            f"{ip_address}"
        )

        # ----------------------------------------------------
        # 1. CHECK WHETHER REGISTRATION IS ENABLED
        # ----------------------------------------------------

        if not registration_allowed:

            message = (
                "❌ Registration is currently not allowed. "
                "Please ask the teacher."
            )

        else:

            # ------------------------------------------------
            # 2. GET VERIFICATION TOKEN
            # ------------------------------------------------

            verification_token = (
                request.form.get(
                    "verification_token",
                    ""
                ).strip()
            )

            # ------------------------------------------------
            # 3. VERIFY TOKEN
            # ------------------------------------------------

            verification_payload = (
                verify_verification_token(
                    verification_token
                )
            )

            if not verification_payload:

                print(
                    "[REGISTRATION] ❌ Invalid or "
                    "expired verification token."
                )

                message = (
                    "❌ Hotspot verification failed. "
                    "Please reconnect to the teacher's "
                    "hotspot and try again."
                )

            else:

                verified_ip = (
                    verification_payload.get("ip")
                )

                # --------------------------------------------
                # 4. MAKE SURE TOKEN BELONGS TO THIS REQUEST
                # --------------------------------------------

                if verified_ip != ip_address:

                    print(
                        "[REGISTRATION] ❌ Token IP "
                        "does not match request IP."
                    )

                    message = (
                        "❌ Verification mismatch. "
                        "Please verify your hotspot connection again."
                    )

                # --------------------------------------------
                # 5. FINAL NETWORK CHECK
                # --------------------------------------------

                elif (
                    not ip_address.startswith(
                        ALLOWED_IP_PREFIX
                    )
                    or ip_address == TEACHER_IP
                ):

                    message = (
                        "❌ You must be connected to the "
                        "teacher's hotspot to register."
                    )

                else:

                    # ----------------------------------------
                    # 6. GET STUDENT INFORMATION
                    # ----------------------------------------

                    name = request.form.get(
                        "name",
                        ""
                    ).strip()

                    mac = request.form.get(
                        "mac",
                        ""
                    ).strip()

                    if not name or not mac:

                        message = (
                            "⚠️ Please fill in all fields."
                        )

                    else:

                        # ------------------------------------
                        # 7. SAVE STUDENT
                        # ------------------------------------

                        with open(
                            "students.csv",
                            mode="a",
                            newline=""
                        ) as file:

                            writer = csv.writer(file)

                            writer.writerow(
                                [
                                    name,
                                    mac
                                ]
                            )

                        print(
                            f"[REGISTRATION] ✅ Student "
                            f"registered: {name}"
                        )

                        message = (
                            "✅ Registered successfully!"
                        )


    return render_template(
        "register.html",
        message=message
    )


# ============================================================
# STUDENT ATTENDANCE
# ============================================================

@app.route(
    "/student",
    methods=["GET", "POST"]
)
def student_page():

    message = ""

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        mac = request.form.get(
            "mac",
            ""
        ).strip()

        ip_address = request.remote_addr

        print(
            f"[DEBUG] Student IP address: "
            f"{ip_address}"
        )

        # ----------------------------------------------------
        # CHECK REGISTRATION
        # ----------------------------------------------------

        registered = False

        try:

            with open(
                "students.csv",
                newline=""
            ) as file:

                reader = csv.reader(file)

                for row in reader:

                    if (
                        len(row) >= 2
                        and row[0] == name
                        and row[1] == mac
                    ):

                        registered = True
                        break

        except FileNotFoundError:

            message = (
                "❌ No registered students found."
            )

            return render_template(
                "student.html",
                message=message
            )


        # ----------------------------------------------------
        # VALIDATION
        # ----------------------------------------------------

        if not registered:

            message = (
                "❌ You are not registered. "
                "Please contact the teacher."
            )

        elif not attendance_status:

            message = (
                "⚠️ Attendance is currently OFF."
            )

        elif (
            not ip_address.startswith(
                ALLOWED_IP_PREFIX
            )
            or ip_address == TEACHER_IP
        ):

            message = (
                "❌ You must be connected to the "
                "teacher’s hotspot "
                f"({ALLOWED_IP_PREFIX}X) "
                "to mark attendance."
            )

        else:

            # ------------------------------------------------
            # PREVENT DUPLICATE ATTENDANCE
            # ------------------------------------------------

            already_marked = False

            try:

                with open(
                    "attendance.csv",
                    newline=""
                ) as file:

                    reader = csv.reader(file)

                    for row in reader:

                        if (
                            len(row) >= 2
                            and row[1] == mac
                        ):

                            already_marked = True
                            break

            except FileNotFoundError:

                pass


            if already_marked:

                message = (
                    "⚠️ Attendance already marked "
                    "for this student."
                )

            else:

                timestamp = (
                    datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )

                with open(
                    "attendance.csv",
                    mode="a",
                    newline=""
                ) as file:

                    writer = csv.writer(file)

                    writer.writerow(
                        [
                            name,
                            mac,
                            ip_address,
                            timestamp
                        ]
                    )

                message = (
                    "✅ Attendance marked successfully!"
                )


    return render_template(
        "student.html",
        message=message
    )


# ============================================================
# VIEW ATTENDANCE
# ============================================================

@app.route("/view")
@teacher_required
def view_attendance():

    records = []

    try:

        with open(
            "attendance.csv",
            newline=""
        ) as file:

            reader = csv.reader(file)

            records = list(reader)

    except FileNotFoundError:

        pass

    return render_template(
        "view.html",
        records=records
    )


# ============================================================
# REGISTERED STUDENTS
# ============================================================

@app.route(
    "/registered_students"
)
@teacher_required
def registered_students():

    students = []

    try:

        with open(
            "students.csv",
            newline=""
        ) as file:

            reader = csv.reader(file)

            students = list(reader)

    except FileNotFoundError:

        pass

    return render_template(
        "registered_students.html",
        students=students
    )


# ============================================================
# CLEAR ATTENDANCE RECORDS
# ============================================================

@app.route(
    "/clear_attendance",
    methods=["POST"]
)
@teacher_required
def clear_attendance():

    try:

        with open(
            "attendance.csv",
            "w",
            newline=""
        ) as file:

            pass

        print(
            "[INFO] Attendance records cleared by teacher."
        )

    except Exception as error:

        print(
            f"[ERROR] Could not clear attendance: "
            f"{error}"
        )

    return redirect(
        url_for("view_attendance")
    )


# ============================================================
# LOCAL VERIFICATION
# ============================================================

@app.route(
    "/local-verification",
    methods=["GET", "OPTIONS"]
)
def local_verification():

    # Handle browser CORS preflight.
    if request.method == "OPTIONS":

        return "", 204


    student_ip = request.remote_addr

    print(
        f"[VERIFICATION] Request received from: "
        f"{student_ip}"
    )


    # --------------------------------------------------------
    # CHECK TEACHER HOTSPOT
    # --------------------------------------------------------

    if (
        not student_ip
        or not student_ip.startswith(
            ALLOWED_IP_PREFIX
        )
        or student_ip == TEACHER_IP
    ):

        print(
            "[VERIFICATION] ❌ Student is not "
            "on the teacher hotspot."
        )

        return {
            "verified": False,
            "message": (
                "Please connect to the teacher's "
                "hotspot."
            )
        }, 403


    # --------------------------------------------------------
    # CREATE TEMPORARY SIGNED TOKEN
    # --------------------------------------------------------

    token, expires_at = (
        create_verification_token(
            student_ip
        )
    )


    print(
        "[VERIFICATION] ✅ Hotspot verified."
    )

    print(
        f"[VERIFICATION] Token expires at: "
        f"{expires_at}"
    )


    return {
        "verified": True,
        "message": (
            "Student is connected to the "
            "teacher hotspot."
        ),
        "token": token,
        "expires_at": expires_at
    }


# ============================================================
# OLD LOCAL VERIFICATION TEST
# ============================================================

@app.route(
    "/local-verification-test"
)
def local_verification_test():

    return {
        "status": "connected",
        "message": (
            "Local AttendX verifier is reachable"
        ),
        "ip": request.remote_addr
    }


# ============================================================
# START FLASK SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )