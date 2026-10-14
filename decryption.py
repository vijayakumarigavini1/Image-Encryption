from cryptography.fernet import Fernet

# Read the secret key
with open("secret.key", "rb") as file:
    key = file.read()

# Create decryption object
cipher = Fernet(key)

# Read encrypted image
with open("encrypted_image.enc", "rb") as file:
    encrypted_data = file.read()

# Decrypt image
decrypted_data = cipher.decrypt(encrypted_data)

# Save decrypted image
with open("decrypted_image.png", "wb") as file:
    file.write(decrypted_data)

print("Image decrypted successfully")