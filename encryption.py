from cryptography.fernet import Fernet

# Generate encryption key
key = Fernet.generate_key()

# Create encryption object
cipher = Fernet(key)

# Read image
with open(r"C:\virat\input.png", "rb") as file:
    image_data = file.read()

# Encrypt image
encrypted_data = cipher.encrypt(image_data)

# Save encrypted data
with open("encrypted_image.enc", "wb") as file:
    file.write(encrypted_data)

# Save key
with open("secret.key", "wb") as file:
    file.write(key)

print("Image encrypted successfully")