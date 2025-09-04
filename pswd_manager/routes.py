from flask import request
from werkzeug.security import check_password_hash
from pswd_manager.crypto_utils import derive_user_key
from pswd_manager import app
from pswd_manager.register_form import RegisterForm
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash
from pswd_manager import app, get_db_connection
from flask import render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash
from pswd_manager.new_password_form import StorePasswordForm
# config.py
from dotenv import load_dotenv
from .crypto_utils import encrypt_password, decrypt_password
import os
from cryptography.fernet import Fernet

load_dotenv()  # take environment variables from .env.

app.config['MYSQL_USER'] = os.environ.get("MYSQL_USER")
app.config['MYSQL_PASSWORD'] = os.environ.get("MYSQL_PASSWORD")
app.config['MYSQL_DB'] = os.environ.get("MYSQL_DB")


FERNET_KEY = os.environ.get("FERNET_KEY") # ek bar generate karke save kar le
cipher = Fernet(FERNET_KEY)


# mysql configuration
app.config['MYSQL_HOST'] = os.environ.get("DB_HOST")


# creating the object of MySQL class
mysql = MySQL(app)


# Now creating the decorators name home page
# If we type /home in URL section then it will give error so we will give two route to single html file
@app.route("/")
@app.route("/Home")
def home_page():
    return render_template("home.html")
            # Here render redirect the html file form webpage folder and process it. 
                            
# Creating a new route for storing password page after register or sign up
@app.route("/manage_password")
def manage_password():
    # Now i will give data to this function and then i will access it from its web page of html
    # Here i am taking user data to display on the home page after login
   
    # creating a dictionary
    password_actions = [
    {"action": "Save Password", "link": "/save_new_password"},
    {"action": "View Password", "link": "/view_stored_password"},
    ]
    return render_template("home_signin.html", data=password_actions)


# Making route for register form.
# Making route for register form.
import os
from werkzeug.security import generate_password_hash

@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password1")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # check duplicate user
        cursor.execute("SELECT * FROM user_account WHERE username = %s OR email = %s", (username, email))
        existing_user = cursor.fetchone()
        if existing_user:
            flash("Username or Email already exists! Please Login here.", "danger")
            cursor.close()
            conn.close()
            return render_template("login_form.html")

        # hash password for authentication
        hashed_password = generate_password_hash(password)

        # generate unique salt for the user
        salt = os.urandom(16)  

        # insert into db
        cursor.execute(
            "INSERT INTO user_account (username, email, password, enc_salt) VALUES (%s, %s, %s, %s)",
            (username, email, hashed_password, salt)
        )
        conn.commit()
        cursor.close()
        conn.close()

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login_page"))

    return render_template("register_page.html", form=RegisterForm())





@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        login_input = request.form.get("login")   # username or email
        password = request.form.get("password")   # entered password

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # get user from db
        cursor.execute("SELECT * FROM user_account WHERE email = %s OR username = %s", (login_input, login_input))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user["password"], password):
            # derive encryption key from entered password + stored salt
            user_key = derive_user_key(password, user["enc_salt"])
            session["user_id"] = user["id"]
            session["user_key"] = user_key.decode()   # save as string for json-safe

            flash("Login successful!", "success")
            return redirect(url_for("manage_password"))
        else:
            flash("Invalid username/email or password!")

    return render_template("login_form.html")



# Creating a route for logout
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("You have been logged out.", "info")

    return redirect(url_for("home_page"))


# Showing the user details on nav bar
@app.context_processor
def inject_user():
    if "user_id" in session:
        user_id = session["user_id"]
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT username FROM user_account WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            username = user["username"]
            username_split = username.split()
            len_username = len(username_split)
            if len_username >= 2:
                username_show = username_split[0][0].upper() + username_split[1][0].upper()
            else:
                username_show = username_split[0][0].upper()
            return dict(username=username, username_show=username_show)

    return dict(username=None, username_show=None)



# Route for saving new password
from pswd_manager.crypto_utils import encrypt_password

@app.route("/save_new_password", methods=["GET", "POST"])
def save_new_password():
    form = StorePasswordForm()
    if form.validate_on_submit():
        name = form.name.data
        address = form.address.data
        password = form.password1.data

        user_id = session.get("user_id")
        user_key = session.get("user_key")   # 🔑 key stored at login

        if not user_id or not user_key:
            flash("You must be logged in to save a password.", "danger")
            return redirect(url_for("login_page"))

        # encrypt password with this user's key
        encrypted_password = encrypt_password(password, user_key)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO stored_passwords (user_id, name, address, password) VALUES (%s, %s, %s, %s)",
            (user_id, name, address, encrypted_password)
        )
        conn.commit()
        cursor.close()
        conn.close()

        flash("Password saved successfully!", "success")
        return redirect(url_for("manage_password"))

    return render_template("new_password_form.html", form=form)


# This is for viewing stored password
from pswd_manager.crypto_utils import decrypt_password

@app.route("/view_stored_password")
def view_stored_password():
    user_id = session.get("user_id")
    user_key = session.get("user_key")   # 🔑 key stored at login

    if not user_id or not user_key:
        flash("Please log in first!", "danger")
        return redirect(url_for("login_page"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, name, address, password FROM stored_passwords WHERE user_id = %s", (user_id,))
    passwords = cursor.fetchall()
    cursor.close()
    conn.close()

    # decrypt each password before showing
    for p in passwords:
        try:
            p["password"] = decrypt_password(p["password"], user_key)
        except Exception:
            p["password"] = "[Decryption failed]"

    return render_template("view_stored_password.html", passwords=passwords)




# Delete password
@app.route("/delete/<int:id>", methods=["POST", "GET"])
def delete_password(id):
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in first!", "danger")
        return redirect(url_for("login_page"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM stored_passwords WHERE id = %s AND user_id = %s", (id, user_id))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Password deleted successfully!", "success")
    return redirect(url_for("view_stored_password"))


# Update/Edit password
@app.route("/update/<int:id>", methods=["GET", "POST"])
def update_password(id):
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in first!", "danger")
        return redirect(url_for("login_page"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch the password entry for this user and id
    cursor.execute("SELECT * FROM stored_passwords WHERE id = %s AND user_id = %s", (id, user_id))
    pw = cursor.fetchone()

    if not pw:
        cursor.close()
        conn.close()
        flash("Password entry not found.", "danger")
        return redirect(url_for("view_stored_password"))

    if request.method == "POST":
        address = request.form["username"]  # 'username' input in form, maps to 'address' in DB
        name = request.form["site"]         # 'site' input in form, maps to 'name' in DB
        password = request.form["password"]

        # Encrypt the password before storing
        encrypted_password = encrypt_password(password)

        try:
            cursor.execute(
                "UPDATE stored_passwords SET name = %s, address = %s, password = %s WHERE id = %s AND user_id = %s",
                (address, name,  encrypted_password, id, user_id)
            )
            conn.commit()
            flash("Password updated successfully!", "success")
            return redirect(url_for("view_stored_password"))
        except Exception as e:
            flash("There was a problem updating the password", "danger")

    cursor.close()
    conn.close()
    # Decrypt password for display in the form
    pw["password"] = decrypt_password(pw["password"])
    return render_template("update_password.html", pw=pw)




# Delete account
@app.route("/delete_account", methods=["POST"])
def delete_account():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in first!", "danger")
        return redirect(url_for("login_page"))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM stored_passwords WHERE user_id = %s", (user_id,))
    cursor.execute("DELETE FROM user_account WHERE id = %s", (user_id,))

    conn.commit()
    cursor.close()
    conn.close()

    session.clear()  # remove all session data
    flash("Your account and all associated passwords have been deleted.", "info")
    return redirect(url_for("home_page"))
