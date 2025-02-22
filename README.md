# Secure Notes App
This app was created as a project for Cybersecurity course at my University. The aim of this project was to create an app for storing notes of logged in users in a secure manner. The app allows user to store text notes (markdown/html). Some notes may be labeled as ciphered, decryption of those notes requires providing a secret password. The app doesn't provide a sophisticated UI since the goal of this project was different.

## Features and security features
* Storing notes styled with markdown/html
* Making notes private/public or shared with a user
* Encryption of notes using AES
* Signing notes using asymmetric RSA encryption - allows to confirm authorship of a note
* Validation of input data with negative approach both on frontend and backend
* Limited informing about erros
* Safe storage of passwords (multiple hashing, salt and pepper)
* Password requirements based on characters and entropy
* Resource Access Management
* Delays and limits of attempts on every endpoint prone to brute force
* NGINX production server
* Encryption connection with the app
* CSRF tokens
* CSP
* Simple honeypots against simple bots
* Disabled Server header
* Registering computers that connect to the account
* Password reset

## Technologies
* Python and its libraries
    * Flask
    * Uwsgi
    * Pyotp
    * Bleach
    * Passlib
    * Pycryptodome
* Docker
* SQLite
* JavaScript
* HTML
* CSS

## Setup
The app is contenerized using docker. The first launch of the up sets up a database. For that reason, the simplest way to start the app is to use provided script `start_app.sh`
