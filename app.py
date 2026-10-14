from pathlib import Path
from io import BytesIO
from flask import Flask, render_template, request, send_file
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.utils import secure_filename

app = Flask(__name__)

MAX_IMAGE_SIZE = 10 * 1024 * 1024
app.config["MAX_CONTENT_LENGTH"] = 15 * 1024 * 1024

ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}


@app.errorhandler(413)
def file_too_large(error):
    return render_template(
        "index.html",
        message="File is too large. Please check the 10 MB image limit.",
        error=True
    ), 413


@app.route("/")
def home():
    return render_template(
        "index.html",
        message=None,
        error=False
    )


@app.route("/encrypt", methods=["POST"])
def encrypt_image():
    uploaded_file = request.files.get("image")

    if not uploaded_file or not uploaded_file.filename:
        return render_template(
            "index.html",
            message="Please select an image to encrypt.",
            error=True
        ), 400

    filename = secure_filename(uploaded_file.filename)
    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        return render_template(
            "index.html",
            message="Upload PNG, JPG, JPEG or WEBP images only.",
            error=True
        ), 400

    image_data = uploaded_file.read(MAX_IMAGE_SIZE + 1)

    if not image_data:
        return render_template(
            "index.html",
            message="The selected file is empty.",
            error=True
        ), 400

    if len(image_data) > MAX_IMAGE_SIZE:
        return render_template(
            "index.html",
            message="Image exceeds the 10 MB limit.",
            error=True
        ), 413

    # Generate a unique key for this encryption operation.
    user_key = Fernet.generate_key()
    user_cipher = Fernet(user_key)

    encrypted_data = user_cipher.encrypt(image_data)

    # Return the encrypted image and key as a ZIP file.
    # This avoids losing the key when the browser handles downloads.
    from zipfile import ZipFile, ZIP_DEFLATED

    package = BytesIO()

    with ZipFile(package, "w", ZIP_DEFLATED) as archive:
        archive.writestr(filename + ".enc", encrypted_data)
        archive.writestr(
            Path(filename).stem + ".key",
            user_key
        )

    package.seek(0)

    return send_file(
        package,
        mimetype="application/zip",
        as_attachment=True,
        download_name=Path(filename).stem + "_encrypted_package.zip"
    )


@app.route("/decrypt", methods=["POST"])
def decrypt_image():
    encrypted_file = request.files.get("encrypted_file")
    key_file = request.files.get("key_file")

    if (
        not encrypted_file
        or not encrypted_file.filename
        or not key_file
        or not key_file.filename
    ):
        return render_template(
            "index.html",
            message="Select both the .enc file and its matching .key file.",
            error=True
        ), 400

    encrypted_filename = secure_filename(encrypted_file.filename)
    key_filename = secure_filename(key_file.filename)

    if not encrypted_filename.lower().endswith(".enc"):
        return render_template(
            "index.html",
            message="Please upload a valid .enc file.",
            error=True
        ), 400

    if not key_filename.lower().endswith(".key"):
        return render_template(
            "index.html",
            message="Please upload the matching .key file.",
            error=True
        ), 400

    encrypted_data = encrypted_file.read(MAX_IMAGE_SIZE + 1024)
    key_data = key_file.read(1024).strip()

    if not encrypted_data or not key_data:
        return render_template(
            "index.html",
            message="The encrypted file or key file is empty.",
            error=True
        ), 400

    try:
        user_cipher = Fernet(key_data)
        decrypted_data = user_cipher.decrypt(encrypted_data)
    except (InvalidToken, ValueError):
        return render_template(
            "index.html",
            message="Decryption failed. The key may be incorrect or the file may be invalid.",
            error=True
        ), 400

    original_name = encrypted_filename[:-4] or "decrypted_image.png"

    return send_file(
        BytesIO(decrypted_data),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=original_name
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
