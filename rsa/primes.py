import math
import random
def sieve_of_eratosthenes(maximum: int):
    primes = [0] * (maximum - 1)
    #0th index = 2
    i = 2
    while i < math.sqrt(maximum):
        if primes[i - 2] == 0:
            for j in range(i**2, maximum+1, i):
                primes[j - 2] = 1
        i += 1
    
    return [x+2 for x in filter(lambda i: primes[i] == 0, range(len(primes)))]

# def miller_rabin_primality_test(x: int):


def is_prime(x: int):
    prime = True
    for p in sieve_of_eratosthenes(10000):
        if x % p == 0 and p != x:
            prime = False
    if p > 10000:
        return False
    return prime
if __name__ == "__main__":
    while True:
        count = 1
        while True:
            if is_prime(random.randrange(1, 10000)):
                    print(f"prime found in {count} attempts")
                    break
            count += 1

