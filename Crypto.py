from PIL import Image


def encrypt(plaintext, key):
    L = plaintext[0]
    R = plaintext[1]
    delta = 0x9E3779B9
    sum = 0
    for i in range(32):
        sum = sum + delta
        L = (L + (((R << 4) + key[0]) ^ (R + sum) ^ ((R >> 5) + key[1]))) % 2 ** 32
        R = (R + (((L << 4) + key[2]) ^ (L + sum) ^ ((L >> 5) + key[3]))) % 2 ** 32

    ciphertext = (L, R)
    return ciphertext


def decrypt(ciphertext, key):
    L = ciphertext[0]
    R = ciphertext[1]
    delta = 0x9E3779B9
    sum = (delta << 5) % 2 ** 32
    for i in range(32):
        R = (R - (((L << 4) + key[2]) ^ (L + sum) ^ ((L >> 5) + key[3]))) % 2 ** 32
        L = (L - (((R << 4) + key[0]) ^ (R + sum) ^ ((R >> 5) + key[1]))) % 2 ** 32
        sum = sum - delta

    ciphertext = (L, R)
    return ciphertext


def list_to_tuple(plaintext_list):
    L = 0
    R = 0
    for i in range(4):
        L <<= 8
        c = ord(plaintext_list[i])
        L += c

    for i in range(4, len(plaintext_list)):
        R <<= 8
        c = ord(plaintext_list[i])
        R += c

    plaintext = (L, R)
    return plaintext


def tuple_to_list(ciphertext_tuple):
    plaintext_list = []
    for element in ciphertext_tuple:
        shift = 24
        mask = 0xFF000000
        for i in range(4):
            c = element & mask
            c = c >> shift
            plaintext_list.append(chr(c))
            mask = mask >> 8
            shift -= 8

    return plaintext_list


def read_image():
    # Open the image file
    image = Image.open("Aqsa.bmp")  # Replace "image_file.jpg" with the path to your image file

    # Convert the image to grayscale
    image = image.convert("L")

    # Resize the image to a smaller size if needed
    # image = image.resize((new_width, new_height))

    # Get the dimensions of the image
    width, height = image.size

    # Load pixel data from the image
    pixel_data = list(image.getdata())

    # Convert pixel values to ASCII characters
    ascii_characters = [chr(pixel) for pixel in pixel_data]

    # Convert the list of ASCII characters to a string
    ascii_string = ''.join(ascii_characters)

    value = (ascii_string, width, height)
    return value


def save_image(data, width, height):
    # Convert the ASCII string back to a list of pixel values
    pixel_values = [ord(char) for char in data]

    # Create an image from the pixel values
    image = Image.new("L", (width, height))
    image.putdata(pixel_values)

    # Save or display the image
    image.save("reconstructed_image.png")  # Save the image
    image.show()  # Display the image


def ecb_encrypt(plaintext, key):
    plaintext = list(plaintext)
    ciphertext = ''.join(plaintext[:80])
    plaintext = plaintext[80:]
    i = 0
    while i < len(plaintext):
        # check if last block is encountered
        block_list = []
        if (i + 8) > len(plaintext):
            block_list = plaintext[i:len(plaintext)]
            # zero-pad the last block
            while len(block_list) != 8:
                block_list.append(chr(0))
        else:
            block_list = plaintext[i:i + 8]

        block = list_to_tuple(block_list)
        cipher = encrypt(block, key)
        cipher_list = tuple_to_list(cipher)
        ciphertext = ciphertext + ''.join(cipher_list)
        i += 8

    return ciphertext


def ecb_decrypt(ciphertext, key):
    ciphertext = list(ciphertext)
    plaintext = ''.join(ciphertext[:80])
    ciphertext = ciphertext[80:]
    i = 0
    while i < len(ciphertext):
        # check if last block is encountered
        if (i + 8) > len(ciphertext):
            block_list = ciphertext[i:len(ciphertext)]
            # zero-pad the last block
            while len(block_list) != 8:
                block_list.append(chr(0))
        else:
            block_list = ciphertext[i:i + 8]

        block = list_to_tuple(block_list)
        decrypted_text = decrypt(block, key)
        decrypted_text_list = tuple_to_list(decrypted_text)
        plaintext = plaintext + ''.join(decrypted_text_list)
        i += 8

    return plaintext


def cbc_encrypt(plaintext, key, IV):
    ci = IV
    plaintext = list(plaintext)
    ciphertext = ''
    i = 0
    while i < len(plaintext):
        # check if last block is encountered
        block_list = []
        if (i + 8) > len(plaintext):
            block_list = plaintext[i:len(plaintext)]
            # zero-pad the last block
            while len(block_list) != 8:
                block_list.append(chr(0))
        else:
            block_list = plaintext[i:i + 8]

        xored = [chr(ord(p) ^ ord(c)) for (p, c) in zip(block_list, ci)]
        xored = list_to_tuple(xored)
        cipher = encrypt(xored, key)
        cipher_list = tuple_to_list(cipher)
        ci = cipher_list
        ciphertext = ciphertext + ''.join(cipher_list)
        i += 8

    return ciphertext


def cbc_decrypt(ciphertext, key, IV):
    ci = IV
    ciphertext = list(ciphertext)
    plaintext = ''
    i = 0
    while i < len(ciphertext):
        # check if last block is encountered
        if (i + 8) > len(ciphertext):
            block_list = ciphertext[i:len(ciphertext)]
            # zero-pad the last block
            while len(block_list) != 8:
                block_list.append(chr(0))
        else:
            block_list = ciphertext[i:i + 8]

        block = list_to_tuple(block_list)
        decrypted_text = decrypt(block, key)
        decrypted_text_list = tuple_to_list(decrypted_text)
        xored = [chr(ord(c) ^ ord(p)) for (p, c) in zip(decrypted_text_list, ci)]
        ci = block_list
        plaintext = plaintext + ''.join(xored)
        i += 8

    return plaintext


key = [0x1234, 0x1234, 0x1234, 0x1234]
IV = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']

print(cbc_decrypt(cbc_encrypt('helloworld', key, IV), key, IV))

plaintext, width, height = read_image()


print('Enter key word by word:')
for i in range(4):
    key[i] = input(f'enter word {3-i}:')
key = [int(word, 16) for word in key]
print(key)

mode = int(input('Choose encryption mode:\n1. ECB\n2. CBC\n'))
if mode == 1:
    ciphertext = ecb_encrypt(plaintext, key)
    plaintext = ecb_decrypt(ciphertext, key)
elif mode == 2:
    IV = int(input('Enter initialization vector (IV):'), 16)
    IV = (IV >> 32, IV & ~(0xFFFFFFFF << 32))
    IV = tuple_to_list(IV)
    ciphertext = cbc_encrypt(plaintext, key, IV)
    plaintext = cbc_decrypt(ciphertext, key, IV)
else:
    print('invalid input')

save_image(plaintext, width, height)


# p = list_to_tuple(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'])
# c = encrypt(p, key)
# print(''.join(tuple_to_list(c)))
# plaintext = decrypt(c, key)
# p = tuple_to_list(plaintext)
# print(''.join(p))
