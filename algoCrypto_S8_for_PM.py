# importation of modules
import random
import math
import sympy
import secrets
from typing import Tuple



# mapping between letters and numbers
decrypt_mapping = {
        # Single digits with leading zeros (01-09)
        '01': '1', '02': '2', '03': '3', '04': '4', '05': '5',
        '06': '6', '07': '7', '08': '8', '09': '9', '00': '0',
        
        # Uppercase base alphabet (11-36)
        '11': 'A', '12': 'B', '13': 'C', '14': 'D', '15': 'E', '16': 'F',
        '17': 'G', '18': 'H', '19': 'I', '20': 'J', '21': 'K', '22': 'L',
        '23': 'M', '24': 'N', '25': 'O', '26': 'P', '27': 'Q', '28': 'R',
        '29': 'S', '30': 'T', '31': 'U', '32': 'V', '33': 'W', '34': 'X',
        '35': 'Y', '36': 'Z',

        # Lowercase base alphabet (46–71)
        '46': 'a', '47': 'b', '48': 'c', '49': 'd', '50': 'e', '51': 'f',
        '52': 'g', '53': 'h', '54': 'i', '55': 'j', '56': 'k', '57': 'l',
        '58': 'm', '59': 'n', '60': 'o', '61': 'p', '62': 'q', '63': 'r',
        '64': 's', '65': 't', '66': 'u', '67': 'v', '68': 'w', '69': 'x',
        '70': 'y', '71': 'z',

        # Lowercase French accented letters (72–87)
        '72': 'à', '73': 'â', '74': 'æ', '75': 'ç', '76': 'é', '77': 'è',
        '78': 'ê', '79': 'ë', '80': 'î', '81': 'ï', '82': 'ô', '83': 'œ',
        '84': 'ù', '85': 'û', '86': 'ü', '87': 'ÿ',

        # Uppercase French accented letters (151-166)
        '151': 'À', '152': 'Â', '153': 'Æ', '154': 'Ç', '155': 'É', '156': 'È',
        '157': 'Ê', '158': 'Ë', '159': 'Î', '160': 'Ï', '161': 'Ô', '162': 'Œ',
        '163': 'Ù', '164': 'Û', '165': 'Ü', '166': 'Ÿ',

        # Basic punctuation and symbols (37-45)
        '37': '@', '38': '#', '39': '$', '40': '%',
        '41': ' ', '42': "'", '43': '.', '44': ',', '45': '?',

        # Extended punctuation and symbols (88–120)
        '88': '!', '89': ':', '90': ';', '91': '-', '92': '(',
        '93': ')', '94': '«', '95': '»', '96': '"', '97': '“',
        '98': '”', '99': '…',
        '100': '&', '101': '*', '102': '+', '103': '=', '104': '/',
        '105': '\\', '106': '|', '107': '[', '108': ']', '109': '{',
        '110': '}', '111': '<', '112': '>', '113': '^', '114': '~',
        '115': '`', '116': '§', '117': '±', '118': '©', '119': '®',
        '120': '™',

        # Additional punctuation and special characters (121-140)
        '121': '€', '122': '£', '123': '¥', '124': '¢', '125': '¤',
        '126': '°', '127': '·', '128': '•', '129': '¶', '130': '†',
        '131': '‡', '132': '‰', '133': '′', '134': '″', '135': '‹',
        '136': '›', '137': '‽', '138': '※', '139': '⁂', '140': ' ',

        # Mathematical symbols (141-150)
        '141': '−', '142': '×', '143': '÷', '144': '±', '145': '∞',
        '146': '≈', '147': '≠', '148': '≤', '149': '≥', '150': '√',
    }


# function to decrypt numbers
def decrypt_number(seq, dec_mapping):
    
    return ''.join(dec_mapping.get(seq[i:i+2], '') for i in range(0, len(seq), 2))

# function to encrypt words
def encrypt_number(text,decrypt_mapping):
    
    encrypt_mapping = {v: k for k, v in decrypt_mapping.items()}

    # Build the ciphertext
    codes = []
    for ch in text:
        code = encrypt_mapping.get(ch)
        if code is None:
            raise ValueError(f"Character not encodable: {repr(ch)}")
        codes.append(code)
    return ''.join(codes)



# function for ElGamal encryption
def elgamal_encrypt(m: int, p: int, g: int, y: int):

    # ephemeral exponent k ∈ {1, …, p-2}
    k = secrets.randbelow(p - 2) + 1

    c1 = pow(g, k, p)
    s  = pow(y, k, p)      # shared secret y^k mod p
    c2 = (m * s) % p
    return c1, c2

# function to decrypt a block of words (ElGamal)
def elgamal_decrypt(c1: int, c2: int, p: int, x: int):
    """
    Textbook ElGamal decryption: m = c2 * (c1^x)^(-1) mod p.
    """
    s = pow(c1, x, p)
    s_inv = pow(s, -1, p)  # Python 3.8+: modular inverse
    return (c2 * s_inv) % p

# function to decrypt a text
def elgamal_decrypt_text(p, a, cipher_text):
    """
        >> decrypt the cipher text in Elgamal cryptosystem
    """
    message_decrypt = []
    for c1, c2 in cipher_text:
        m = int(int(pow(c1, -a, p))* c2) % p
        message_decrypt.append(m)
    return message_decrypt


# for concatenate a list
def concatenation(list_):
    """
       [1, 2, 3, 4]  >> '1234'
    """
    
    return ''.join(str(e) for e in list_)


# function to generate the keys
def elgamal_keygen(p: int, g: int):
    """
    Generate a private/public key pair (x, y) for fixed (p, g).
    x ∈ {1, …, p-2}, y = g^x mod p.
    """
    x = secrets.randbelow(p - 2) + 1
    y = pow(g, x, p)
    return x, y


################################################################################################

# fumctions to find the safe prime p and generator g

def is_generator(g,p):
    """
        Test if g is a generator for the Fp
    """
    for f in sympy.factorint(p-1):
        if pow(g,p//f,p)==1:
            return False
    return True
    
def find_generator(n:int):
    """
        Find a generetor for Z/nZ
    """
    while True:
        k = random.randint(2,n-1)
        if is_generator(k,n):
            return k


def is_prime_1(n:int):
    """
        Test of primary for n
    """
    a = random.randint(0,n-1)
    s = 0
    t = n-1

    while(t%2==0):
        t = t >> 1
        s = s + 1

    x = pow(a,t,n)
    if x ==1:
        return True
        
    for _ in range(0,s):
        if x==n-1:
            return True
        x = (x*x)%n
    return False

def is_prime_miller(n,nbr_test = 500):
    """
        Miller Rabin test of primary
    """
    for _ in range(nbr_test):
        if is_prime_1(n):
            return True
    return False


def generate_safe_prime(n:int):
    """
        Generates a safe prime p such that x/ln^2(x) < p <= x, where x = 2^n.
    """

    x = pow(2, n)
    ln_2_x = int(pow(math.log(x), 2))
    y0 = int((x - ln_2_x) // (2 * ln_2_x))
    y1 = int(pow(2, n-1) - 1)
    
    for i in range(500):
        b = random.randint(y0, y1)
        if is_prime_miller(b) and is_prime_miller(2*b + 1):
            return 2*b + 1

    raise ValueError("Failed to generate a safe prime within the given constraints.")


################################################################################################



if __name__ == "__main__":
    p_ = 123456789987654353003 

    message_encrypted = [
        (83025882561049910713, 66740266984208729661),
        (117087132399404660932, 44242256035307267278),
        (67508282043396028407, 77559274822593376192),
        (60938739831689454113, 14528504156719159785),
        (5059840044561914427, 59498668430421643612),
        (92232942954165956522, 105988641027327945219),
        (97102226574752360229, 46166643538418294423),
    ]

    seq_decryp = elgamal_decrypt_text(p_, 5191, message_encrypted)
    print(seq_decryp)

    ad = concatenation(seq_decryp)
    print(decrypt_number(ad, decrypt_mapping))

    print("++"*15)

    ################################################################################################


    # 768-bit prime
    p = 208351617316091241234326746312124448251235562226470491514186331217050270460481 
    g = 2

    # Key generation
    x, y = elgamal_keygen(p, g)
    print(x, y)

    # Encrypt integer message (e.g., m = 42)
    c1, c2 = elgamal_encrypt(42, p, g, y)

    # Decrypt
    m_recovered = elgamal_decrypt(c1, c2, p, x)
    assert m_recovered == 42


    print("\n")
    seq = "mila Vita ity ee!?"
    seq_num = encrypt_number(seq, decrypt_mapping)
    print(seq, seq_num)

    c1, c2 = elgamal_encrypt(int(seq_num), p, g, y)

    dec = elgamal_decrypt(c1, c2, p, x)
    txt = decrypt_number(str(dec), decrypt_mapping)
    print(dec, txt)


    print("++"*15)
    plaintext = "AKory aby ee!!"
    cipher = encrypt_number(plaintext, decrypt_mapping)
    recovered = decrypt_number(cipher, decrypt_mapping)
    print(cipher)      # e.g., "4715605944964150747241..." (depends on mapping)

    print(recovered) 
    assert recovered == plaintext