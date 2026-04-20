from flask import Flask, render_template, request
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

# GENERAR CLAVES
@app.route('/generar')
def generar():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return "Claves generadas"

# FIRMAR
@app.route('/firmar', methods=['POST'])
def firmar():
    archivo = request.files['archivo']
    archivo.save("documento.txt")

    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open("documento.txt", "rb") as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open("firma.bin", "wb") as f:
        f.write(signature)

    return "Documento firmado"

# VERIFICAR
@app.route('/verificar', methods=['POST'])
def verificar():
    archivo = request.files['archivo']
    archivo.save("verificar.txt")

    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    with open("verificar.txt", "rb") as f:
        data = f.read()

    with open("firma.bin", "rb") as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return "Firma válida ✔ Documento original"
    except InvalidSignature:
        return "Firma inválida ❌ Documento alterado"

# PAGINA PRINCIPAL
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)