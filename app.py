from flask import Flask, render_template, request, jsonify
import hashlib
import binascii

app = Flask(__name__)

# Fungsi Inti: Menghitung WPA2 Key (PBKDF2)
def compute_wpa2(passphrase, ssid):
    # WPA2 menggunakan 4096 iterasi HMAC-SHA1
    dk = hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), 4096, 32)
    return binascii.hexlify(dk).decode()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/audit', methods=['POST'])
def run_audit():
    ssid = request.form.get('ssid')
    target_hash = request.form.get('target_hash') # Hash dari file .cap
    
    found_password = None
    try:
        with open('wordlist.txt', 'r', encoding='latin-1') as f:
            for line in f:
                pwd = line.strip()
                # Proses audit pencocokan
                if compute_white_hash(pwd, ssid) == target_hash:
                    found_password = pwd
                    break
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

    if found_password:
        return jsonify({"status": "success", "password": found_password})
    else:
        return jsonify({"status": "failed", "message": "Password tidak ditemukan dalam wordlist."})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
