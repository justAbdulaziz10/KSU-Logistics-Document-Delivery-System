import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import hashlib
import datetime
import random
import pyotp
import qrcode
import tkintermapview
import os
import sys
import tkinter
import tkinter.messagebox
from tkintermapview import TkinterMapView

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def log_transaction(action, details):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("transactions.log", "a") as log_file:
        log_file.write(f"{timestamp} - {action}: {details}\n")

def create_database():
    conn = sqlite3.connect("ksu_logistics.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT,
        last_name TEXT,
        user_class TEXT,
        user_id TEXT UNIQUE,
        password_hash TEXT,
        email TEXT UNIQUE,
        phone TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS packages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tracking_number TEXT UNIQUE,
        sender_id TEXT,
        receiver_id TEXT,
        dimensions TEXT,
        weight REAL,
        status TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    try:
        cursor.execute("ALTER TABLE packages ADD COLUMN source_office_id TEXT")
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE packages ADD COLUMN destination_office_id TEXT")
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE packages ADD COLUMN current_lat REAL")
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE packages ADD COLUMN current_lng REAL")
    except sqlite3.OperationalError:
        pass

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logistics_offices (
        id TEXT PRIMARY KEY,
        name TEXT,
        lat REAL,
        lng REAL
    )
    """)

    conn.commit()
    conn.close()

def view_package_map(tracking_number):
    conn = sqlite3.connect("ksu_logistics.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT 
        l1.lat AS source_lat, l1.lng AS source_lng, 
        l2.lat AS dest_lat, l2.lng AS dest_lng,
        p.current_lat, p.current_lng
    FROM packages p
    JOIN logistics_offices l1 ON l1.id = p.source_office_id
    JOIN logistics_offices l2 ON l2.id = p.destination_office_id
    WHERE p.tracking_number = ?
    """, (tracking_number,))
    data = cursor.fetchone()
    conn.close()

    if not data:
        messagebox.showerror("Error", "Package not found.")
        return

    source_lat, source_lng, dest_lat, dest_lng, current_lat, current_lng = data

    map_window = tk.Toplevel()
    map_window.title("Package Map View")
    map_window.geometry("800x600")

    map_widget = tkintermapview.TkinterMapView(map_window, width=800, height=600, corner_radius=0)
    map_widget.pack(fill=tk.BOTH, expand=True)

    map_widget.set_position(source_lat, source_lng)
    map_widget.set_zoom(15)

    map_widget.set_marker(source_lat, source_lng, text="Source Office")
    map_widget.set_marker(dest_lat, dest_lng, text="Destination Office")

    if current_lat and current_lng:
        current_marker = map_widget.set_marker(current_lat, current_lng, text="Current Location")
    else:
        current_marker = None

    def add_custom_pin():
        try:
            lat = float(entry_lat.get())
            lng = float(entry_lng.get())
            text = entry_text.get().strip()
            pin_location_on_map(map_widget, lat, lng, text)
        except ValueError:
            messagebox.showerror("Error", "Invalid latitude or longitude. Please enter numeric values.")

    def pin_location_on_map(map_widget, lat, lng, text="Custom Pin"):

        map_widget.set_marker(lat, lng, text=text)

    pin_frame = tk.Frame(map_window)
    pin_frame.pack(fill=tk.X, pady=5)

    tk.Label(pin_frame, text="Latitude:").grid(row=0, column=0, padx=5)
    entry_lat = tk.Entry(pin_frame, width=10)
    entry_lat.grid(row=0, column=1, padx=5)

    tk.Label(pin_frame, text="Longitude:").grid(row=0, column=2, padx=5)
    entry_lng = tk.Entry(pin_frame, width=10)
    entry_lng.grid(row=0, column=3, padx=5)

    tk.Label(pin_frame, text="Text:").grid(row=0, column=4, padx=5)
    entry_text = tk.Entry(pin_frame, width=15)
    entry_text.grid(row=0, column=5, padx=5)

    tk.Button(pin_frame, text="Add Pin", command=add_custom_pin).grid(row=0, column=6, padx=5)

    path = map_widget.set_path([(source_lat, source_lng), (dest_lat, dest_lng)])

    def update_current_location():
        nonlocal current_marker
        conn = sqlite3.connect("ksu_logistics.db")
        cursor = conn.cursor()
        cursor.execute("SELECT current_lat, current_lng FROM packages WHERE tracking_number = ?", (tracking_number,))
        new_location = cursor.fetchone()
        conn.close()

        if new_location and new_location[0] and new_location[1]:
            new_lat, new_lng = new_location
            if current_marker:
                current_marker.set_position(new_lat, new_lng)
            else:
                current_marker = map_widget.set_marker(new_lat, new_lng, text="Current Location")
        map_window.after(5000, update_current_location)  # Refresh every 5 seconds

    update_current_location()


def create_office():
    def save_office():
        office_id = entry_office_id.get().strip()
        office_name = entry_office_name.get().strip()
        lat, lng = map_widget.get_position()

        if not office_id or not office_name:
            messagebox.showerror("Error", "Office ID and Office Name cannot be empty.")
            return

        conn = sqlite3.connect("ksu_logistics.db")
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO logistics_offices (id, name, lat, lng) VALUES (?, ?, ?, ?)",
                           (office_id, office_name, lat, lng))
            conn.commit()
            log_transaction("Admin Action", f"Created logistics office {office_id} - {office_name}")
            messagebox.showinfo("Success", "Logistics Office created successfully!")
            office_window.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Office ID already exists.")
        finally:
            conn.close()

    office_window = tk.Toplevel()
    office_window.title("Create Logistics Office")
    office_window.geometry("800x600")

    tk.Label(office_window, text="Office ID:").pack(pady=5)
    entry_office_id = tk.Entry(office_window, width=30)
    entry_office_id.pack(pady=5)

    tk.Label(office_window, text="Office Name:").pack(pady=5)
    entry_office_name = tk.Entry(office_window, width=30)
    entry_office_name.pack(pady=5)


    tk.Label(office_window, text="Pin Office Location on Map:").pack(pady=5)
    map_widget = tkintermapview.TkinterMapView(office_window, width=700, height=400, corner_radius=0)
    map_widget.set_position(24.7136, 46.6753)#riyadh
    map_widget.set_zoom(8)
    map_widget.pack(pady=5)

    def add_pin():
        lat, lng = map_widget.get_position()
        map_widget.set_marker(lat, lng, text="Office Location")

    tk.Button(office_window, text="Add Pin", command=add_pin).pack(pady=5)
    tk.Button(office_window, text="Save Office", command=save_office).pack(pady=10)


def sign_up():
    def validate_inputs():
        first_name = entry_first_name.get().strip()
        last_name = entry_last_name.get().strip()
        user_class = user_class_var.get()
        user_id = entry_user_id.get().strip()
        password = entry_password.get()
        email = entry_email.get().strip()
        phone = entry_phone.get().strip()

        # Input Validation
        if not first_name or not last_name:
            messagebox.showerror("Error", "First Name and Last Name cannot be empty.")
            return False

        if user_class not in ["Student", "Faculty", "Employee", "Admin", "Courier"]:
            messagebox.showerror("Error", "Invalid User Class selected.")
            return False

        if (user_class == "Student" and len(user_id) != 10) or (user_class in ["Faculty", "Employee", "Admin", "Courier"] and len(user_id) != 6):
            messagebox.showerror("Error", f"{user_class} ID must be {'10' if user_class == 'Student' else '6'} digits.")
            return False

        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long.")
            return False

        if not email.endswith("@ksu.edu.sa") or "@" not in email:
            messagebox.showerror("Error", "Invalid email format. Email must end with '@ksu.edu.sa'.")
            return False

        if not phone.startswith("05") or len(phone) != 10 or not phone.isdigit():
            messagebox.showerror("Error", "Phone number must be in the format 05XXXXXXXX.")
            return False

        return True

    def submit():
        if not validate_inputs():
            return


        first_name = entry_first_name.get().strip()
        last_name = entry_last_name.get().strip()
        user_class = user_class_var.get()
        user_id = entry_user_id.get().strip()
        password_hash = hash_password(entry_password.get())
        email = entry_email.get().strip()
        phone = entry_phone.get().strip()

        conn = sqlite3.connect("ksu_logistics.db")
        cursor = conn.cursor()

        try:
            cursor.execute("""
            INSERT INTO users (first_name, last_name, user_class, user_id, password_hash, email, phone)
            VALUES (?, ?, ?, ?, ?, ?, ?)""", (first_name, last_name, user_class, user_id, password_hash, email, phone))
            conn.commit()
            log_transaction("Sign-Up", f"User {user_id} signed up.")
            messagebox.showinfo("Success", "User registered successfully!")
            root.destroy()
            login()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "User ID or email already exists.")
        finally:
            conn.close()

    def open_login():
        root.destroy()
        login()

    root = tk.Tk()
    root.title("KSU Logistics - Sign Up")
    root.geometry("600x500")
    root.configure(bg="#f0f0f0")

    header_frame = tk.Frame(root, bg="#004d99", height=80)
    header_frame.pack(fill=tk.X)

    header_label = tk.Label(header_frame, text="KSU Logistics - Sign Up", bg="#004d99", fg="white", font=("Arial", 20, "bold"))
    header_label.pack(pady=20)

    frame = ttk.Frame(root, padding=20)
    frame.pack(fill=tk.BOTH, expand=True)

    ttk.Label(frame, text="First Name:").grid(row=0, column=0, sticky=tk.W, pady=5)
    entry_first_name = ttk.Entry(frame, width=30)
    entry_first_name.grid(row=0, column=1, pady=5)

    ttk.Label(frame, text="Last Name:").grid(row=1, column=0, sticky=tk.W, pady=5)
    entry_last_name = ttk.Entry(frame, width=30)
    entry_last_name.grid(row=1, column=1, pady=5)

    ttk.Label(frame, text="User Class:").grid(row=2, column=0, sticky=tk.W, pady=5)
    user_class_var = tk.StringVar(value="Student")
    user_class_dropdown = ttk.Combobox(frame, textvariable=user_class_var, values=["Student", "Faculty", "Employee", "Admin", "Courier"], state="readonly", width=27)
    user_class_dropdown.grid(row=2, column=1, pady=5)

    ttk.Label(frame, text="User ID:").grid(row=3, column=0, sticky=tk.W, pady=5)
    entry_user_id = ttk.Entry(frame, width=30)
    entry_user_id.grid(row=3, column=1, pady=5)

    ttk.Label(frame, text="Password:").grid(row=4, column=0, sticky=tk.W, pady=5)
    entry_password = ttk.Entry(frame, show="*", width=30)
    entry_password.grid(row=4, column=1, pady=5)

    ttk.Label(frame, text="Email:").grid(row=5, column=0, sticky=tk.W, pady=5)
    entry_email = ttk.Entry(frame, width=30)
    entry_email.grid(row=5, column=1, pady=5)

    ttk.Label(frame, text="Phone:").grid(row=6, column=0, sticky=tk.W, pady=5)
    entry_phone = ttk.Entry(frame, width=30)
    entry_phone.grid(row=6, column=1, pady=5)

    ttk.Button(frame, text="Submit", command=submit).grid(row=7, column=0, columnspan=2, pady=10)
    ttk.Button(frame, text="Go to Login", command=open_login).grid(row=8, column=0, columnspan=2, pady=5)

    root.mainloop()

def login():
    def authenticate():
        user_id = entry_user_id.get().strip()
        password = entry_password.get()

        if not user_id or not user_id.isdigit():
            messagebox.showerror("Error", "User ID must be numeric.")
            return

        if not password:
            messagebox.showerror("Error", "Password cannot be empty.")
            return

        password_hash = hash_password(password)

        conn = sqlite3.connect("ksu_logistics.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE user_id=? AND password_hash=?", (user_id, password_hash))
        user = cursor.fetchone()
        conn.close()

        if user:
            messagebox.showinfo("Success", "Login successful!")
            log_transaction("Login", f"User {user_id} logged in.")
            root.destroy()

            user_class = user[3]
            if user_class == "Admin":
                admin_window()
            elif user_class == "Courier":
                courier_window()
            else:
                user_window(user_id)
        else:
            messagebox.showerror("Error", "Invalid User ID or Password.")

    root = tk.Tk()
    root.title("KSU Logistics - Login")
    root.geometry("600x400")
    root.configure(bg="#f0f0f0")

    header_frame = tk.Frame(root, bg="#004d99", height=80)
    header_frame.pack(fill=tk.X)

    header_label = tk.Label(header_frame, text="KSU Logistics - Login", bg="#004d99", fg="white", font=("Arial", 20, "bold"))
    header_label.pack(pady=20)

    frame = ttk.Frame(root, padding=20)
    frame.pack(fill=tk.BOTH, expand=True)

    ttk.Label(frame, text="User ID:").grid(row=0, column=0, pady=10, sticky=tk.W)
    entry_user_id = ttk.Entry(frame, width=30)
    entry_user_id.grid(row=0, column=1, pady=10)

    ttk.Label(frame, text="Password:").grid(row=1, column=0, pady=10, sticky=tk.W)
    entry_password = ttk.Entry(frame, show="*", width=30)
    entry_password.grid(row=1, column=1, pady=10)

    ttk.Button(frame, text="Login", command=authenticate).grid(row=2, column=0, columnspan=2, pady=20)

    root.mainloop()

def user_window(current_user_id):
    def fetch_offices():
        conn = sqlite3.connect("ksu_logistics.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM logistics_offices")
        offices = cursor.fetchall()
        conn.close()
        return [f"{office[0]} - {office[1]}" for office in offices]

    def drop_package():
        logistics_office = logistics_office_var.get()
        dimensions = entry_dimensions.get().strip()
        weight = entry_weight.get().strip()
        receiver_id = entry_receiver_id.get().strip()
        destination_office = destination_office_var.get()

        if not logistics_office or logistics_office == "Select Office":
            messagebox.showerror("Error", "Please select a source logistics office.")
            return

        if not destination_office or destination_office == "Select Office":
            messagebox.showerror("Error", "Please select a destination logistics office.")
            return

        if not dimensions or "x" not in dimensions:
            messagebox.showerror("Error", "Enter dimensions in the format Length x Width x Height.")
            return

        if not weight or not weight.isdigit():
            messagebox.showerror("Error", "Enter a valid weight in numeric format.")
            return

        if not receiver_id or not receiver_id.isdigit() or len(receiver_id) not in [6, 10]:
            messagebox.showerror("Error", "Receiver ID must be 6 or 10 digits.")
            return

        tracking_number = str(random.randint(10 ** 15, 10 ** 16 - 1))
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        source_office_id = logistics_office.split(" - ")[0]
        destination_office_id = destination_office.split(" - ")[0]

        conn = sqlite3.connect("ksu_logistics.db")
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO packages (tracking_number, sender_id, receiver_id, dimensions, weight, status, timestamp, source_office_id, destination_office_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                           (tracking_number, current_user_id, receiver_id, dimensions, weight, "In Transit", timestamp,
                            source_office_id, destination_office_id))
            conn.commit()
            log_transaction("Package Dropped", f"Tracking {tracking_number} by {current_user_id}")
            messagebox.showinfo("Success", f"Package dropped! Tracking Number: {tracking_number}")
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"Failed to drop package: {e}")
        finally:
            conn.close()

    def view_packages():
        conn = sqlite3.connect("ksu_logistics.db")
        cursor = conn.cursor()
        cursor.execute("""
            SELECT tracking_number, dimensions, weight, receiver_id, status, timestamp
            FROM packages
            WHERE sender_id=?""",
            (current_user_id,))
        packages = cursor.fetchall()
        conn.close()

        packages_window = tk.Toplevel(root)
        packages_window.title("My Packages")

        if not packages:
            tk.Label(packages_window, text="No packages found.", font=("Arial", 12)).pack(pady=20)
            return

        for idx, package in enumerate(packages, start=1):
            package_info = f"""
            {idx}. Tracking Number: {package[0]}
                Dimensions: {package[1]}, Weight: {package[2]}kg
                Receiver ID: {package[3]}, Status: {package[4]}
                Timestamp: {package[5]}
            """
            tk.Label(packages_window, text=package_info, font=("Arial", 10), justify=tk.LEFT).pack(pady=5)

    def logout():
        log_transaction("User Logout", f"User {current_user_id} logged out")
        root.destroy()
        sign_up()

    root = tk.Tk()
    root.title("User Panel")
    root.geometry("700x500")
    root.configure(bg="#f0f0f0")

    header_frame = tk.Frame(root, bg="#004d99", height=80)
    header_frame.pack(fill=tk.X)

    header_label = tk.Label(header_frame, text="User Panel", bg="#004d99", fg="white", font=("Arial", 20, "bold"))
    header_label.pack(pady=20)

    tab_control = ttk.Notebook(root)

    tab_drop_package = ttk.Frame(tab_control)
    tab_control.add(tab_drop_package, text="Drop Package")

    logistics_offices = fetch_offices()
    ttk.Label(tab_drop_package, text="Logistics Office (Source):").grid(row=0, column=0, pady=10, sticky=tk.W)
    logistics_office_var = tk.StringVar(value="Select Office")
    ttk.Combobox(tab_drop_package, textvariable=logistics_office_var, values=logistics_offices, state="readonly",
                 width=30).grid(row=0, column=1, pady=10)

    ttk.Label(tab_drop_package, text="Destination Office:").grid(row=1, column=0, pady=10, sticky=tk.W)
    destination_office_var = tk.StringVar(value="Select Office")
    ttk.Combobox(tab_drop_package, textvariable=destination_office_var, values=logistics_offices, state="readonly",
                 width=30).grid(row=1, column=1, pady=10)

    ttk.Label(tab_drop_package, text="Dimensions (LxWxH):").grid(row=2, column=0, pady=10, sticky=tk.W)
    entry_dimensions = ttk.Entry(tab_drop_package, width=30)
    entry_dimensions.grid(row=2, column=1, pady=10)

    ttk.Label(tab_drop_package, text="Weight (kg):").grid(row=3, column=0, pady=10, sticky=tk.W)
    entry_weight = ttk.Entry(tab_drop_package, width=30)
    entry_weight.grid(row=3, column=1, pady=10)

    ttk.Label(tab_drop_package, text="Receiver ID:").grid(row=4, column=0, pady=10, sticky=tk.W)
    entry_receiver_id = ttk.Entry(tab_drop_package, width=30)
    entry_receiver_id.grid(row=4, column=1, pady=10)

    ttk.Button(tab_drop_package, text="Submit", command=drop_package).grid(row=5, column=0, columnspan=2, pady=20)

    tab_view_packages = ttk.Frame(tab_control)
    tab_control.add(tab_view_packages, text="View My Packages")

 #   ttk.Button(tab_view_packages, text="View Package Map",
  #             command=lambda: view_package_map("tracking_number_here")).pack(pady=10)

    ttk.Button(tab_view_packages, text="View Packages", command=view_packages).pack(pady=20)

    tab_control.pack(expand=True, fill=tk.BOTH)
    ttk.Button(root, text="Logout", command=logout).pack(pady=10)

    root.mainloop()

def admin_window():
    def create_office():
        def save_office():
            office_id = entry_office_id.get().strip()
            office_name = entry_office_name.get().strip()
            lat, lng = map_widget.get_position()

            if not office_id or not office_name:
                messagebox.showerror("Error", "Office ID and Office Name cannot be empty.")
                return

            conn = sqlite3.connect("ksu_logistics.db")
            cursor = conn.cursor()

            try:
                cursor.execute("INSERT INTO logistics_offices (id, name, lat, lng) VALUES (?, ?, ?, ?)",
                               (office_id, office_name, lat, lng))
                conn.commit()
                log_transaction("Admin Action", f"Created logistics office {office_id} - {office_name}")
                messagebox.showinfo("Success", "Logistics Office created successfully!")
                office_window.destroy()
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "Office ID already exists.")
            finally:
                conn.close()

        office_window = tk.Toplevel()
        office_window.title("Create Logistics Office")
        office_window.geometry("800x600")

        tk.Label(office_window, text="Office ID:").pack(pady=5)
        entry_office_id = tk.Entry(office_window, width=30)
        entry_office_id.pack(pady=5)

        tk.Label(office_window, text="Office Name:").pack(pady=5)
        entry_office_name = tk.Entry(office_window, width=30)
        entry_office_name.pack(pady=5)

        # Add the map
        tk.Label(office_window, text="Pin Office Location on Map:").pack(pady=5)
        map_widget = tkintermapview.TkinterMapView(office_window, width=700, height=400, corner_radius=0)
        map_widget.set_position(24.7136, 46.6753)
        map_widget.set_zoom(8)
        map_widget.pack(pady=5)

        def add_pin():
            lat, lng = map_widget.get_position()
            map_widget.set_marker(lat, lng, text="Office Location")

        tk.Button(office_window, text="Add Pin", command=add_pin).pack(pady=5)
        tk.Button(office_window, text="Save Office", command=save_office).pack(pady=10)

    def backup_data():
        conn = sqlite3.connect("ksu_logistics.db")
        cursor = conn.cursor()

        with open("backup.csv", "w") as file:
            file.write("Table,Data\n")
            for table in ["users", "packages", "logistics_offices"]:
                cursor.execute(f"SELECT * FROM {table}")
                rows = cursor.fetchall()
                file.write(f"{table},{rows}\n")

        conn.close()
        log_transaction("Admin Action", "Backup created")
        messagebox.showinfo("Success", "Backup completed and saved as 'backup.csv'.")

    def logout():
        log_transaction("Admin Action", "Admin logged out")
        root.destroy()
        sign_up()

    root = tk.Tk()
    root.title("Admin Panel")
    root.geometry("600x400")
    root.configure(bg="#f0f0f0")

    header_frame = tk.Frame(root, bg="#004d99", height=80)
    header_frame.pack(fill=tk.X)

    header_label = tk.Label(header_frame, text="Admin Panel", bg="#004d99", fg="white", font=("Arial", 20, "bold"))
    header_label.pack(pady=20)

    frame = ttk.Frame(root, padding=20)
    frame.pack(fill=tk.BOTH, expand=True)

    ttk.Button(frame, text="Create Logistics Office", command=create_office).pack(pady=10)
    ttk.Button(frame, text="Backup Data", command=backup_data).pack(pady=5)
    ttk.Button(frame, text="Logout", command=logout).pack(pady=10)

    root.mainloop()

def courier_window():
    def accept_package():
        sender_id = entry_accept_sender_id.get().strip()
        tracking_number = entry_accept_tracking_number.get().strip()

        if not sender_id or not sender_id.isdigit() or len(sender_id) not in [6, 10]:
            messagebox.showerror("Error", "Invalid Sender User ID. It must be 6 or 10 digits.")
            return

        if not tracking_number or len(tracking_number) != 16 or not tracking_number.isdigit():
            messagebox.showerror("Error", "Invalid Tracking Number. It must be 16 digits.")
            return

        conn = sqlite3.connect("ksu_logistics.db")
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT * FROM packages WHERE sender_id=? AND tracking_number=?", (sender_id, tracking_number))
            package = cursor.fetchone()

            if not package:
                messagebox.showerror("Error", "Package not found. Please check the details and try again.")
                return

            cursor.execute("UPDATE packages SET status='Accepted at Logistics Office' WHERE tracking_number=?", (tracking_number,))
            conn.commit()
            log_transaction("Accept Package", f"Sender: {sender_id}, Tracking: {tracking_number}, Status: Accepted")
            messagebox.showinfo("Success", "Package marked as 'Accepted at Logistics Office'.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to accept package: {e}")
        finally:
            conn.close()

    def deliver_package():
        sender_id = entry_deliver_sender_id.get().strip()
        tracking_number = entry_deliver_tracking_number.get().strip()

        if not sender_id or not sender_id.isdigit() or len(sender_id) not in [6, 10]:
            messagebox.showerror("Error", "Invalid Sender User ID. It must be 6 or 10 digits.")
            return

        if not tracking_number or len(tracking_number) != 16 or not tracking_number.isdigit():
            messagebox.showerror("Error", "Invalid Tracking Number. It must be 16 digits.")
            return

        conn = sqlite3.connect("ksu_logistics.db")
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT * FROM packages WHERE sender_id=? AND tracking_number=?", (sender_id, tracking_number))
            package = cursor.fetchone()

            if not package:
                messagebox.showerror("Error", "Package not found. Please check the details and try again.")
                return

            cursor.execute("UPDATE packages SET status='Delivered' WHERE tracking_number=?", (tracking_number,))
            conn.commit()
            log_transaction("Deliver Package", f"Sender: {sender_id}, Tracking: {tracking_number}, Status: Delivered")
            messagebox.showinfo("Success", "Package marked as 'Delivered'.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to deliver package: {e}")
        finally:
            conn.close()

    def logout():
        log_transaction("Courier Logout", "Courier logged out")
        root.destroy()
        sign_up()

    root = tk.Tk()
    root.title("Courier Panel")
    root.geometry("600x400")
    root.configure(bg="#f0f0f0")

    header_frame = tk.Frame(root, bg="#004d99", height=80)
    header_frame.pack(fill=tk.X)

    header_label = tk.Label(header_frame, text="Courier Panel", bg="#004d99", fg="white", font=("Arial", 20, "bold"))
    header_label.pack(pady=20)

    tab_control = ttk.Notebook(root)

    tab_accept_package = ttk.Frame(tab_control)
    tab_control.add(tab_accept_package, text="Accept a Package")

    ttk.Label(tab_accept_package, text="Sender User ID:").grid(row=0, column=0, pady=10, sticky=tk.W)
    entry_accept_sender_id = ttk.Entry(tab_accept_package, width=30)
    entry_accept_sender_id.grid(row=0, column=1, pady=10)

    ttk.Label(tab_accept_package, text="Tracking Number:").grid(row=1, column=0, pady=10, sticky=tk.W)
    entry_accept_tracking_number = ttk.Entry(tab_accept_package, width=30)
    entry_accept_tracking_number.grid(row=1, column=1, pady=10)

    ttk.Button(tab_accept_package, text="Accept Package", command=accept_package).grid(row=2, column=0, columnspan=2, pady=20)

    tab_deliver_package = ttk.Frame(tab_control)
    tab_control.add(tab_deliver_package, text="Deliver a Package")

    ttk.Label(tab_deliver_package, text="Sender User ID:").grid(row=0, column=0, pady=10, sticky=tk.W)
    entry_deliver_sender_id = ttk.Entry(tab_deliver_package, width=30)
    entry_deliver_sender_id.grid(row=0, column=1, pady=10)

    ttk.Label(tab_deliver_package, text="Tracking Number:").grid(row=1, column=0, pady=10, sticky=tk.W)
    entry_deliver_tracking_number = ttk.Entry(tab_deliver_package, width=30)
    entry_deliver_tracking_number.grid(row=1, column=1, pady=10)

    ttk.Button(tab_deliver_package, text="Deliver Package", command=deliver_package).grid(row=2, column=0, columnspan=2, pady=20)

    tab_control.pack(expand=True, fill=tk.BOTH)
    ttk.Button(root, text="Logout", command=logout).pack(pady=10)

    root.mainloop()


if __name__ == "__main__":
    create_database()
    sign_up()
