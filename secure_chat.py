import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import requests
import socketio
from Crypto.Cipher import AES
import base64
import pyaudio
import wave
import threading
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, send
import bcrypt

# ---------------- Flask Server (Backend) ----------------
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
SECRET_KEY = b'abcdefghijklmnop'

# Database setup
import json

def save_message(user, message):
    data = {"user": user, "message": message}
    with open("messages.json", "a") as file:
        json.dump(data, file)
        file.write("\n")

def load_messages():
    messages = []
    try:
        with open("messages.json", "r") as file:
            for line in file:
                messages.append(json.loads(line))
    except FileNotFoundError:
        pass
    return messages

def pad_message(message):
    return message + (16 - len(message) % 16) * chr(16 - len(message) % 16)

def encrypt_message(message):
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    encrypted_bytes = cipher.encrypt(pad_message(message).encode())
    return base64.b64encode(encrypted_bytes).decode()

def decrypt_message(encrypted_message):
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(base64.b64decode(encrypted_message)).decode()
    return decrypted_bytes.rstrip('\x10')

messages = []

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username, password = data["username"], data["password"]
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    cursor.execute("INSERT INTO users VALUES (?, ?)", (username, hashed_pw))
    conn.commit()
    return jsonify({"message": "User registered successfully!"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username, password = data["username"], data["password"]
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    record = cursor.fetchone()
    if record and bcrypt.checkpw(password.encode(), record[0]):
        return jsonify({"message": "Login successful!"})
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@socketio.on("message")
def handle_message(encrypted_msg):
    messages.append(encrypted_msg)
    send(encrypted_msg, broadcast=True)

@app.route("/get_messages", methods=["GET"])
def get_messages():
    return {"messages": messages}

# Start server in a separate thread
def start_server():
    socketio.run(app, host="127.0.0.1", port=5000, debug=False)

threading.Thread(target=start_server, daemon=True).start()

# ---------------- Tkinter Chat UI (Frontend) ----------------
sio = socketio.Client()

def connect_socket():
    sio.connect("http://127.0.0.1:5000")

def send_message():
    message = entry.get()
    if not message:
        messagebox.showwarning("Warning", "Message cannot be empty!")
        return
    encrypted_msg = encrypt_message(message)
    sio.send(encrypted_msg)
    entry.delete(0, tk.END)

def load_messages():
    chat_box.config(state=tk.NORMAL)
    chat_box.delete(1.0, tk.END)
    response = requests.get("http://127.0.0.1:5000/get_messages").json()
    for msg in response["messages"]:
        try:
            decrypted_msg = decrypt_message(msg)
            chat_box.insert(tk.END, f"{decrypted_msg}\\n", "message")
        except:
            pass
    chat_box.config(state=tk.DISABLED)

@sio.on("message")
def receive_message(encrypted_msg):
    load_messages()

# ---------------- Voice Message Recording ----------------
def record_audio():
    filename = filedialog.asksaveasfilename(defaultextension=".wav", filetypes=[("WAV files", "*.wav")])
    if not filename:
        return
    audio = pyaudio.PyAudio()
    stream = audio.open(format=pyaudio.paInt16, channels=1, rate=44100, input=True, frames_per_buffer=1024)
    frames = []

    messagebox.showinfo("Recording", "Recording... Click OK to stop.")
    while True:
        try:
            data = stream.read(1024)
            frames.append(data)
        except:
            break

    stream.stop_stream()
    stream.close()
    audio.terminate()

    with wave.open(filename, 'wb') as wf:
        wf.setnchannels(1)
        wf.setsampwidth(audio.get_sample_size(pyaudio.paInt16))
        wf.setframerate(44100)
        wf.writeframes(b''.join(frames))

    messagebox.showinfo("Saved", f"Voice message saved as {filename}")

# ---------------- File Sharing ----------------
def send_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        messagebox.showinfo("File Sent", f"File {file_path} sent successfully!")

# ---------------- Login Screen ----------------
def login_screen():
    login_window = tk.Toplevel(root)
    login_window.title("Login")
    login_window.geometry("300x200")

    tk.Label(login_window, text="Username").pack(pady=5)
    username_entry = tk.Entry(login_window)
    username_entry.pack(pady=5)

    tk.Label(login_window, text="Password").pack(pady=5)
    password_entry = tk.Entry(login_window, show="*")
    password_entry.pack(pady=5)

    def attempt_login():
        username, password = username_entry.get(), password_entry.get()
        response = requests.post("http://127.0.0.1:5000/login", json={"username": username, "password": password})
        if response.status_code == 200:
            messagebox.showinfo("Login Successful", "Welcome to Secure Chat!")
            login_window.destroy()
            connect_socket()
        else:
            messagebox.showerror("Error", "Invalid Credentials!")

    tk.Button(login_window, text="Login", command=attempt_login).pack(pady=10)

# ---------------- UI Setup ----------------
root = tk.Tk()
root.title("Secure Messenger")
root.geometry("400x600")
root.configure(bg="#2c3e50")

chat_box = scrolledtext.ScrolledText(root, state=tk.DISABLED, wrap=tk.WORD, height=15, bg="#ecf0f1")
chat_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
chat_box.tag_config("message", foreground="blue")

entry = tk.Entry(root, font=("Arial", 14), bg="#bdc3c7")
entry.pack(padx=10, pady=5, fill=tk.X)

button_frame = tk.Frame(root, bg="#2c3e50")
button_frame.pack(fill=tk.X)

tk.Button(button_frame, text="Send", command=send_message, bg="#27ae60", fg="white").pack(side=tk.LEFT, expand=True, padx=5, pady=5)
tk.Button(button_frame, text="Record", command=record_audio, bg="#f39c12", fg="white").pack(side=tk.LEFT, expand=True, padx=5, pady=5)
tk.Button(button_frame, text="File", command=send_file, bg="#3498db", fg="white").pack(side=tk.LEFT, expand=True, padx=5, pady=5)

login_screen()
root.mainloop()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=10000, debug=False)
