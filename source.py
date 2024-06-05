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


def read_image(path):
    # Open the image file
    image = Image.open(path)  # open the image specified by the given path

    # Convert the image to grayscale
    image = image.convert("L")

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


def save_image(data, width, height, name):
    # Convert the ASCII string back to a list of pixel values
    pixel_values = [ord(char) for char in data]

    # Create an image from the pixel values
    image = Image.new("L", (width, height))
    image.putdata(pixel_values)

    # Save or display the image
    image.save(name)  # Save the image
    image.show()  # Display the image


def ecb_encrypt(plaintext, key):
    plaintext = list(plaintext)
    # leave the first 10 blocks unencrypted
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
    # retrieve the first 10 unencrypted blocks
    plaintext = ''.join(ciphertext[:80])
    ciphertext = ciphertext[80:]

    i = 0
    while i < len(ciphertext):
        # check if last block is encountered, 8 is the block size in bytes
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
    # leave the first 10 blocks unencrypted
    ciphertext = ''.join(plaintext[:80])
    plaintext = plaintext[80:]

    i = 0
    while i < len(plaintext):
        # check if last block is encountered, 8 is the block size in bytes
        block_list = []
        if (i + 8) > len(plaintext):
            block_list = plaintext[i:len(plaintext)]
            # zero-pad the last block
            while len(block_list) != 8:
                block_list.append(chr(0))
        else:
            block_list = plaintext[i:i + 8]

        # In CBC, ci = enc(ci-1 xor pi), compute xored = ci-1 xor pi, compute for every byte of xored
        xored = [chr(ord(p) ^ ord(c)) for (p, c) in zip(block_list, ci)]
        xored = list_to_tuple(xored)
        cipher = encrypt(xored, key)  # ci = enc(xored)
        cipher_list = tuple_to_list(cipher)
        ci = cipher_list
        ciphertext = ciphertext + ''.join(cipher_list)
        i += 8

    return ciphertext


def cbc_decrypt(ciphertext, key, IV):
    ci = IV
    ciphertext = list(ciphertext)
    plaintext = ''.join(ciphertext[:80])
    ciphertext = ciphertext[80:]

    i = 0
    while i < len(ciphertext):
        # check if last block is encountered, 8 is the block size in bytes
        if (i + 8) > len(ciphertext):
            block_list = ciphertext[i:len(ciphertext)]
            # zero-pad the last block
            while len(block_list) != 8:
                block_list.append(chr(0))
        else:
            block_list = ciphertext[i:i + 8]

        block = list_to_tuple(block_list)
        decrypted_text = decrypt(block, key)  # In CBC, there is a need to compute dec(ci)
        decrypted_text_list = tuple_to_list(decrypted_text)
        # In CBC, pi = ci-1 xor dec(ci), compute for every byte of pi
        xored = [chr(ord(c) ^ ord(p)) for (p, c) in zip(decrypted_text_list, ci)]
        ci = block_list
        plaintext = plaintext + ''.join(xored)
        i += 8

    return plaintext


def main():
    # initialize key and IV
    key = [0, 0, 0, 0]  # key consists of 4 words initialized to 0
    IV = [0, 0]  # IV consists of 2 words initialized to 0

    # the path of the image is entered here and the image is read along with its dimensions
    path = input('Enter the path of the image: ')
    plaintext, width, height = read_image(path)

    # the key with which the image is encrypted is entered here
    print('Enter key word by word (8 hex digits each): ')
    for i in range(4):
        key[i] = input(f'enter word {3 - i}: ')
    key = [int(word, 16) for word in key]

    mode = int(input('Choose encryption mode:\n1. ECB\n2. CBC\n'))
    if mode == 1:
        ciphertext = ecb_encrypt(plaintext, key)
        save_image(ciphertext, width, height, 'ecb_encrypted_image.bmp')
        plaintext = ecb_decrypt(ciphertext, key)
        save_image(plaintext, width, height, 'ecb_decrypted_image.bmp')
    elif mode == 2:
        IV = int(input('Enter initialization vector (IV) [64 bits or 16 hex digits]:'), 16)
        IV = (IV >> 32, IV & ~(0xFFFFFFFF << 32))  # convert the 64-bit IV to a tuple of 32-bit in each part
        IV = tuple_to_list(IV)  # convert the tuple to a list, since the encryption algorithm deals with lists
        ciphertext = cbc_encrypt(plaintext, key, IV)
        save_image(ciphertext, width, height, 'cbc_encrypted_image.bmp')
        plaintext = cbc_decrypt(ciphertext, key, IV)
        save_image(plaintext, width, height, 'cbc_decrypted_image.bmp')
    else:
        print('invalid input')

    print('images saved.')


if __name__ == '__main__':
    main()
