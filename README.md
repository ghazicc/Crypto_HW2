# Image Encryption and Decryption

This Python program encrypts and decrypts images using the ECB (Electronic Codebook) and CBC (Cipher Block Chaining) encryption modes, with the TEA encryption algorithm used therein. The user is prompted to enter the path of the image, a 128-bit key (provided as four 32-bit hexadecimal words), and optionally an initialization vector (IV) for CBC mode. The program then displays and saves the encrypted and decrypted images.

## Features

- Supports ECB and CBC encryption modes.
- Allows user input for the image path, encryption key, and IV (for CBC mode).
- Displays and saves the encrypted and decrypted images.

## Prerequisites

- Python 3.x
- Required libraries: `PIL` (Pillow)

## Installation

1. Clone the repository:

   git clone https://github.com/ghazicc/Crypto_HW2.git
   cd Crypto_HW2

2. Install the required libraries:

   pip install pillow

## Usage

1. Run the program:

   python source.py

2. Follow the prompts to enter the necessary information:

   - **Image Path**: Enter the path to the image file you want to encrypt.
   - **128-bit Key**: Enter the 128-bit key as four 32-bit hexadecimal words (e.g., `0x2b7e1516 0x28aed2a6 0xabf7cf0e 0x889d4038`).
   - **Encryption Mode**: Choose between `ECB` and `CBC`.
     - If `CBC` is chosen, you will be prompted to enter an initialization vector (IV) in hexadecimal format.

3. The program will display the encrypted and decrypted images and save them to the current directory.


## Acknowledgments

- [Pillow](https://python-pillow.org/) - A Python Imaging Library (PIL) fork.
