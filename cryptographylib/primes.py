import math
import random


def sieve_of_eratosthenes(maximum: int) -> list:
    """Perform the sieve of Eratosthenes to calculate all primes up to a given integer.

    Args:
        maximum (int): The upper limit for primes calculates 

    Returns:
        list: All the primes up to the maximum
    """
    primes = [0] * (maximum - 1)
    # 0th index = 2
    i = 2
    while i < math.sqrt(maximum):
        if primes[i - 2] == 0:
            for j in range(i ** 2, maximum + 1, i):
                primes[j - 2] = 1
        i += 1

    return [x + 2 for x in filter(lambda i: primes[i] == 0, range(len(primes)))]

primes_up_to_1_million = sieve_of_eratosthenes(1000000) # calculated on module import 
def miller_rabin_primality_test(n: int, r: int):
        if n % 2 == 0:
            return False
        u = n - 1
        k = 0
        # need u to be odd and u * 2^k == n - 1
        while u % 2 == 0:
            u //= 2
            k += 1
        
        for i in range(r):
            a = random.randrange(1, n - 1)
            b = pow(a, u, n)
            if b == 1 or b == n - 1:
                continue
            
            check_next = False
            for j in range(k - 1):
                b = pow(b, 2, n)
                if b == n - 1:
                    check_next = True # likely is prime
                    break
            if not check_next:
                return False # not prime
        return True

def is_prime(x: int):
    for p in primes_up_to_1_million:
        if x % p == 0 and p != x:
            return False
    if miller_rabin_primality_test(x, 100):
        return True
    return False
   


if __name__ == "__main__":
    count = 1
    while True:
        candidate = random.randrange(1, 2**2048)
        if is_prime(candidate):
            print(f"prime found in {count} attempts")
            print(candidate)
            break
        count += 1
