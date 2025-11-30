from flask import Flask, request, render_template, send_file, flash, redirect, url_for, session
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np
import base64
import io
import sqlite3
import secrets
import telepot

admin=telepot.Bot("")

# Helper functions for padding and unpadding
def pad(data, block_size=16):
    padding = block_size - len(data) % block_size
    return data + bytes([padding] * padding)

def unpad(data):
    padding = data[-1]
    return data[:-padding]

# Encrypt data using SM4 (AES in ECB mode for simplicity)
def sm4_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data))

# Decrypt data using SM4
def sm4_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data))

# Embed data into an image
def embed_data_in_image(image, data):
    img = Image.open(image)
    img = img.convert('RGB')
    img_data = np.array(img)

    flat_img = img_data.flatten()
    data_length = len(data)
    metadata = data_length.to_bytes(4, 'big')

    combined_data = metadata + data
    if len(combined_data) * 8 > len(flat_img):
        raise ValueError("Data is too large to fit in the image.")

    for i in range(len(combined_data)):
        byte = combined_data[i]
        for bit_pos in range(8):
            bit = (byte >> (7 - bit_pos)) & 0x01
            flat_img[i * 8 + bit_pos] = (flat_img[i * 8 + bit_pos] & 0xFE) | bit

    new_img_data = flat_img.reshape(img_data.shape)
    new_img = Image.fromarray(new_img_data, 'RGB')
    output_image = io.BytesIO()
    new_img.save(output_image, format="PNG")
    output_image.seek(0)
    new_img.save('static/output.png', format="PNG")

# Extract data from an image
def extract_data_from_image(image):
    img = Image.open(image)
    img_data = np.array(img).flatten()

    metadata_bits = [img_data[i] & 0x01 for i in range(32)]
    metadata_bytes = bytearray()
    for i in range(0, len(metadata_bits), 8):
        byte = 0
        for bit in metadata_bits[i:i + 8]:
            byte = (byte << 1) | bit
        metadata_bytes.append(byte)

    data_length = int.from_bytes(metadata_bytes, 'big')
    data_bits = [img_data[i + 32] & 0x01 for i in range(data_length * 8)]
    data = bytearray()
    for i in range(0, len(data_bits), 8):
        byte = 0
        for bit in data_bits[i:i + 8]:
            byte = (byte << 1) | bit
        data.append(byte)
    return bytes(data)



from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np
import base64
import io

# Helper functions for padding and unpadding
def pad(data, block_size=16):
    padding = block_size - len(data) % block_size
    return data + bytes([padding] * padding)

def unpad(data):
    padding = data[-1]
    return data[:-padding]

# Encrypt data using SM4 (AES in ECB mode for simplicity)
def sm4_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data))

# Decrypt data using SM4
def sm4_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data))

# Embed encrypted image data into a carrier image
def embed_image_in_image(carrier_image_path, hidden_image_path, output_image_path, encrypted_key):
    # Load carrier and hidden images
    carrier_img = Image.open(carrier_image_path).convert('RGB')
    hidden_img = Image.open(hidden_image_path).convert('RGB')

    # Convert hidden image to bytes
    hidden_img_bytes = io.BytesIO()
    hidden_img.save(hidden_img_bytes, format='PNG')
    hidden_data = hidden_img_bytes.getvalue()

    # Encrypt the hidden image data
    key = base64.b64decode(encrypted_key)
##    admin.sendMessage("",str(key))
    encrypted_data = sm4_encrypt(hidden_data, key)

    # Flatten carrier image data
    carrier_data = np.array(carrier_img).flatten()

    # Embed metadata (length of encrypted data) + encrypted data
    data_length = len(encrypted_data)
    metadata = data_length.to_bytes(4, 'big')  # Store length in 4 bytes
    combined_data = metadata + encrypted_data

    if len(combined_data) * 8 > len(carrier_data):
        raise ValueError("Hidden image data is too large to fit in the carrier image.")

    for i, byte in enumerate(combined_data):
        for bit_pos in range(8):
            bit = (byte >> (7 - bit_pos)) & 0x01
            carrier_data[i * 8 + bit_pos] = (carrier_data[i * 8 + bit_pos] & 0xFE) | bit

    # Reshape and save the new image
    new_carrier_data = carrier_data.reshape(np.array(carrier_img).shape)
    new_carrier_img = Image.fromarray(new_carrier_data, 'RGB')
    new_carrier_img.save(output_image_path)

# Extract and decrypt hidden image data
def extract_image_from_image(encrypted_image_path, encrypted_key):
    # Load the encrypted carrier image
    carrier_img = Image.open(encrypted_image_path)
    carrier_data = np.array(carrier_img).flatten()

    # Extract metadata (length of encrypted data)
    metadata_bits = []
    for i in range(32):  # 4 bytes * 8 bits
        metadata_bits.append(carrier_data[i] & 0x01)

    metadata_bytes = bytearray()
    for i in range(0, len(metadata_bits), 8):
        byte = 0
        for bit in metadata_bits[i:i+8]:
            byte = (byte << 1) | bit
        metadata_bytes.append(byte)

    data_length = int.from_bytes(metadata_bytes, 'big')

    # Extract encrypted data
    encrypted_data_bits = []
    for i in range(32, 32 + data_length * 8):
        encrypted_data_bits.append(carrier_data[i] & 0x01)

    encrypted_data = bytearray()
    for i in range(0, len(encrypted_data_bits), 8):
        byte = 0
        for bit in encrypted_data_bits[i:i+8]:
            byte = (byte << 1) | bit
        encrypted_data.append(byte)

    # Decrypt the data
    key = base64.b64decode(encrypted_key)
    decrypted_data = sm4_decrypt(bytes(encrypted_data), key)
    

    # Convert decrypted data back to an image
    hidden_img = Image.open(io.BytesIO(decrypted_data))
    return hidden_img



connection = sqlite3.connect('database.db')
cursor = connection.cursor()

command = """CREATE TABLE IF NOT EXISTS admin (Id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, password TEXT, mobile TEXT, email TEXT)"""
cursor.execute(command)

command = """CREATE TABLE IF NOT EXISTS user (Id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, password TEXT, mobile TEXT, email TEXT)"""
cursor.execute(command)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

@app.route('/')
def index():
    return render_template('index.html')

@app.route("/Text")
def Text():
    return render_template("adminlog.html")

@app.route("/Images")
def Images():
    return render_template("Images.html")

@app.route('/user')
def user():
    return render_template('userlog.html')

@app.route('/adminlog', methods=['GET', 'POST'])
def adminlog():
    if request.method == 'POST':

        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()

        email = request.form['name']
        password = request.form['password']

        query = "SELECT * FROM admin WHERE email = '"+email+"' AND password= '"+password+"'"
        cursor.execute(query)

        result = cursor.fetchone()

        if result:
            return render_template('adminlog.html')
        else:
            return render_template('index.html', msg='Sorry, Incorrect Credentials Provided,  Try Again')
    return render_template('index.html')

@app.route('/adminreg', methods=['GET', 'POST'])
def adminreg():
    if request.method == 'POST':

        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()

        name = request.form['name']
        password = request.form['password']
        mobile = request.form['phone']
        email = request.form['email']
        
        print(name, mobile, email, password)

        cursor.execute("INSERT INTO admin VALUES (NULL, '"+name+"', '"+password+"', '"+mobile+"', '"+email+"')")
        connection.commit()

        return render_template('index.html', msg='Successfully Registered')
    
    return render_template('index.html')


@app.route('/userlog', methods=['GET', 'POST'])
def userlog():
    if request.method == 'POST':

        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()

        email = request.form['name']
        password = request.form['password']

        query = "SELECT * FROM user WHERE email = '"+email+"' AND password= '"+password+"'"
        cursor.execute(query)
        result = cursor.fetchone()

        if result:
            return render_template('userlog.html')
        else:
            return render_template('index.html', msg='Sorry, Incorrect Credentials Provided,  Try Again')

    return render_template('index.html')

@app.route('/userreg', methods=['GET', 'POST'])
def userreg():
    if request.method == 'POST':

        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()

        name = request.form['name']
        password = request.form['password']
        mobile = request.form['phone']
        email = request.form['email']
        
        print(name, mobile, email, password)

        cursor.execute("INSERT INTO user VALUES (NULL, '"+name+"', '"+password+"', '"+mobile+"', '"+email+"')")
        connection.commit()

        return render_template('index.html', msg='Successfully Registered')
    
    return render_template('index.html')

@app.route('/logout')
def logout():
    return render_template('index.html')



@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    if request.method == "POST":
        text = request.form["text"].encode()
        image = request.form["image"]

        key = get_random_bytes(16)
        encrypted_text = sm4_encrypt(text, key)

        # Save encrypted text and key to txt files
        with open("encrypted_data.txt", "wb") as enc_file:
            enc_file.write(encrypted_text)

        with open("encryption_key.txt", "wb") as key_file:
            key_file.write(base64.b64encode(key))
            print(base64.b64encode(key))
            admin=telepot.Bot("")
            admin.sendMessage("",str("Secret key for text encryption "))
            admin.sendMessage("",str(base64.b64encode(key)))
        embed_data_in_image('static/images/'+image, encrypted_text)
        
        return render_template("adminlog.html", download_name='http://127.0.0.1:5000/static/output.png')
    return render_template("adminlog.html")

@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    if request.method == "POST":
        image = 'static/'+request.form["image"]
        key1 = request.form['text']

        with open("encryption_key.txt", "r") as key_file:
                key2 = key_file.read()
        print(key2 , key1)
        if key2 == key1:
            admin=telepot.Bot("")
            admin.sendMessage("",str("admin accessing data"))
            try:
                with open("encryption_key.txt", "rb") as key_file:
                    key = base64.b64decode(key_file.read())

                extracted_data = extract_data_from_image(image)
                decrypted_text = sm4_decrypt(extracted_data, key).decode("utf-8")

                with open("decrypted_text.txt", "w") as dec_file:
                    dec_file.write(decrypted_text)

                return render_template("adminlog.html", decrypted_text=decrypted_text.split(','))
            except Exception as e:
                return render_template("adminlog.html", decrypted_text=["Data not found"])
        else:
            return render_template("adminlog.html", decrypted_text=["Entered wrong key"])
    return render_template("adminlog.html", decrypted_text=None)


@app.route("/imageencrypt", methods=["GET", "POST"])
def imageencrypt():
    if request.method == "POST":
        carrier_image_path = 'static/images/'+request.form["image1"]
        hidden_image_path = 'static/images/'+request.form["image2"]
        output_image_path = "static/output_carrier.png"

        # Generate a random encryption key
        key = get_random_bytes(16)
        encrypted_key = base64.b64encode(key).decode()
        print(f"Generated Key (Keep this safe!): {encrypted_key}")

        with open("encryption_key_image.txt", "wb") as key_file:
            key_file.write(base64.b64encode(key))
            print(base64.b64encode(key))
            admin=telepot.Bot("")
            admin.sendMessage("",str("Secret key for text encryption "))
            admin.sendMessage("",str(base64.b64encode(key)))
        embed_image_in_image(carrier_image_path, hidden_image_path, output_image_path, encrypted_key)
        print(f"Hidden image embedded into {output_image_path}.")
        
        return render_template("images.html", download_name='http://127.0.0.1:5000/static/output_carrier.png')
    return render_template("images.html")

@app.route("/userdecrypt", methods=["GET", "POST"])
def userdecrypt():
    if request.method == "POST":
        image = 'static/'+request.form["image"]
        key1 = request.form['text']

        with open("encryption_key.txt", "r") as key_file:
                key2 = key_file.read()
        print(key2 , key1)
        
        if key2 == key1:
            try:
                with open("encryption_key.txt", "rb") as key_file:
                    key = base64.b64decode(key_file.read())

                extracted_data = extract_data_from_image(image)
                decrypted_text = sm4_decrypt(extracted_data, key).decode("utf-8")

                with open("decrypted_text.txt", "w") as dec_file:
                    dec_file.write(decrypted_text)

                return render_template("userlog.html", decrypted_text=decrypted_text.split(','))
            except Exception as e:
                return render_template("userlog.html", decrypted_text=["Data not found"])
        else:
            return render_template("userlog.html", decrypted_text=["Entered wrong key"])
    return render_template("userlog.html", decrypted_text=None)


@app.route("/userimagedecrypt", methods=["GET", "POST"])
def userimagedecrypt():
    if request.method == "POST":
        encrypted_image_path = 'static/'+request.form["image"]
        key1 = request.form['text']

        with open("encryption_key_image.txt", "r") as key_file:
                key2 = key_file.read()

        print(key2 , key1)
        if key2 == key1:
            try:
                hidden_img = extract_image_from_image(encrypted_image_path, key1)
                hidden_img.show()  # Display the hidden image
                hidden_img.save("static/extracted_hidden_image.png")

                return render_template("userlog.html", decrypted_image='http://127.0.0.1:5000/static/extracted_hidden_image.png')
            except Exception as e:
                print(e)
                return render_template("userlog.html", decrypted_text=["Data not found"])
        else:
            return render_template("userlog.html", decrypted_text=["Entered wrong key"])
    return render_template("userlog.html", decrypted_text=None)

@app.route("/imagedecrypt", methods=["GET", "POST"])
def imagedecrypt():
    if request.method == "POST":
        encrypted_image_path = 'static/'+request.form["image"]
        key1 = request.form['text']

        with open("encryption_key_image.txt", "r") as key_file:
                key2 = key_file.read()

        print(key2 , key1)
        
        if key2 == key1:
            admin=telepot.Bot("")
            admin.sendMessage("",str("admin accessing data"))
            try:
                hidden_img = extract_image_from_image(encrypted_image_path, key1)
                hidden_img.show()  # Display the hidden image
                hidden_img.save("static/extracted_hidden_image.png")

                return render_template("userlog.html", decrypted_image='http://127.0.0.1:5000/static/extracted_hidden_image.png')
            except Exception as e:
                print(e)
                return render_template("userlog.html", decrypted_text=["Data not found"])
        else:
            return render_template("userlog.html", decrypted_text=["Entered wrong key"])
    return render_template("userlog.html", decrypted_text=None)

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
