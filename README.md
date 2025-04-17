# 🔐 Streamlit Data Encryption and Decryption System

A simple encryption and decryption system built using **Streamlit** and **Cryptography**. This app allows users to securely encrypt and decrypt data with a user-provided key.

## 🛠 Features

- **Generate Encryption Key**: Generate a new encryption key for securing data.
- **Encrypt Data**: Encrypt user-inputted text with a generated or provided encryption key.
- **Decrypt Data**: Decrypt previously encrypted data using the correct key.

## 📜 How to Use

- **Home**: Welcome screen with basic instructions about the app.
- **Generate Key**: Generates an encryption key for data encryption.
- **Encrypt**: Input the data to encrypt, along with the encryption key.
- **Decrypt**: Input the encrypted data and the key to decrypt it.

## 📌 Example Usage

### Generate Key:
1. Click on the **Generate Key** tab to generate an encryption key. Save the key for future use.

### Encrypt Data:
1. Go to the **Encrypt** tab.
2. Enter the data you want to encrypt.
3. Enter the encryption key.
4. Click on **Encrypt** to encrypt the data.

### Decrypt Data:
1. Go to the **Decrypt** tab.
2. Enter the encrypted data.
3. Enter the encryption key.
4. Click on **Decrypt** to decrypt the data.

## 🔑 How Encryption Works

- The app uses the **Fernet** encryption scheme from the **cryptography** library to securely encrypt and decrypt data.
- The encryption key is generated using the **Fernet.generate_key()** method.
- For encryption, data is encoded, then encrypted with the Fernet key.
- For decryption, the encrypted data is decrypted back into its original form using the same key.

## 🛠 Technologies Used

- **Streamlit**: For building the web interface.
- **Cryptography**: For secure encryption and decryption.

## 🚀 Run the App

You can run this app locally or use [Streamlit](https://streamlit.io/) to deploy it online:

4. Open the app in your browser at `http://localhost:8501` to interact with it.

## 🧑‍🤝‍🧑 Contributing

Feel free to fork the repository and create a pull request with your improvements or bug fixes.
or details.
