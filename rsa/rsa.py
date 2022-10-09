import random

def gcd_extended_euclid(a,b):
    # this method calculates the greatest common divisor of a and b as well as x and y such that ax + by = gcd(a, b)
    if(a == 0):
        return [b, 0, 1]
    [gcd, x, y] = gcd_extended_euclid(b%a, a)
    return [gcd, y - x * (b//a), x]

#def generate_keypair(keylength: int):
#    base_random_number = random.randrange(2**(keylength-1) + 1, 2**keylength - 1) # 100000000....1 < n < 1111111111...1
    
def calculate_keys(p, q, e):
    # p and q must be very large prime numbers
    # e must be coprime to and less than (p-1) * (q-1)

    # calculate the modulus and public key
    n = p*q
    public_key = [e, n]
    
    phi = (p-1)*(q-1)
    
    # here d is the private key exponent and is chosen such that (d * e) mod phi = 1
    
    # this works as the extended euclidean algorithm returns d and a such that  (d * e) + (a * phi) = 1.
    # when both sides are taken modulo phi we get ((d * e) + (a * phi)) mod phi = 1 mod phi
    # ((d * e) + (a * phi)) mod phi can be expanded to (d * e) mod phi + (a * phi) mod phi by the laws of modular arithmetic 
    # (a * phi) mod phi must always be 0 as (a * phi) is a multiple of phi
    # this gives (d * e) mod phi + 0 = 1 mod phi
    # 1 mod phi = 1
    # therefore we are left with d such that (d * e) mod phi = 1

    [gcd, d, null] = gcd_extended_euclid(e, phi)
    
    d = (d % phi + phi) % phi # this is to eliminate the possibility of negative values for d
    if(e >= phi or gcd != 1): # e must be coprime to phi
        print("INVALID EXPONENT.")
        return
    private_key = [d, n]
    return [public_key, private_key]

def encrypt(plaintext: int, exponent:int, modulus:int):
    return pow(plaintext, exponent, modulus)

def decrypt(ciphertext: int, exponent:int, modulus: int):
    return pow(ciphertext, exponent, modulus)

