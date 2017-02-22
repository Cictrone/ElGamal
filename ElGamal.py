import sys
import math
from random import SystemRandom
from data import ct_pairs


class ElGamal():
    a = None # Private Key set to null initially

    def __init__(self, p, alpha, beta):
        self.p = p
        self.alpha = alpha
        self.beta = beta
        self.a = None

    def setPrivateKey(self, a):
        self.a = a

    # Will find log_alpha(b) with Shanks' Algorithm
    def discreteLog(self, b):
        m = math.ceil(math.sqrt(self.p))
        L_1 = []
        L_2 = []
        alpha_inv = self.modInverse(self.alpha)

        for j in range(m):
            L_1.append((j, self.raiseByExponent(self.alpha, m*j)))

            alpha_neg_j = self.raiseByExponent(alpha_inv, j)
            L_2.append((j, self.multiply(alpha_neg_j, b)))

        L_1.sort(key=lambda x: x[1])
        L_2.sort(key=lambda x: x[1])
        for first in L_1:
            for second in L_2:
                if(first[1] == second[1]):
                    return (m*first[0] + second[0]) % self.p
        return None

    def decrypt(self, y_1, y_2):
        if self.a is None:
            print("You must add the private key to decrypt.")
            return None
        new_y_1 = self.raiseByExponent(y_1, self.a)
        inverse_y_1 = self.modInverse(new_y_1)
        return self.multiply(y_2, inverse_y_1)

    def encrypt(self, x, k=None):
        if k is None:
            rand = SystemRandom()
            k = rand.randrange(3,  self.p-1) # range used to be safe
        y_1 = self.raiseByExponent(self.alpha, k)
        beta_exp = self.raiseByExponent(self.beta, k)
        y_2 = self.multiply(beta_exp, x)
        return (y_1, y_2)

    def modInverse(self, element):
        return self.raiseByExponent(element, self.p-2)

    def raiseByExponent(self, element, exp):
        if exp is 1:
            return element
        gArray = []
        gArray.append(element)
        r = self.multiply(element, element)
        gArray.append(r)

        for i in range(2, exp.bit_length()):
            r = self.multiply(r, r)
            gArray.append(r)

        lowestBit = 0
        for i in range(exp.bit_length()):
            if ((exp & (1 << i)) != 0):
                lowestBit = i
                break
        r = gArray[lowestBit]
        lowestBit += 1

        for i in range(lowestBit, exp.bit_length()):
            if ((exp & (1 << i)) != 0):
                r = self.multiply(r, gArray[i])
        return r

    def multiply(self, e_0, e_1):
        return (e_0 * e_1) % self.p


def numbersToText(numbers):
    L_1 = numbers % 26
    numbers -= L_1
    numbers //= 26
    L_2 = numbers % 26
    numbers -= L_2
    numbers //= 26
    L_3 = numbers % 26
    char_1 = chr(L_1 + 97)
    char_2 = chr(L_2 + 97)
    char_3 = chr(L_3 + 97)
    return char_3 + char_2 + char_1


if __name__ == '__main__':
    if (len(sys.argv) is not 5 and len(sys.argv) is not 4):
        print("python ElGamal.py <p> <alpha> <beta> [a]")
        sys.exit(1)

    p = int(sys.argv[1])
    alpha = int(sys.argv[2])
    beta = int(sys.argv[3])
    cryptosystem = ElGamal(p, alpha, beta)


    if(len(sys.argv) is 5):
        a = int(sys.argv[4])
    else:
        print("Private Key not given, trying discrete logarithm...")
        a = cryptosystem.discreteLog(beta)

    cryptosystem.setPrivateKey(a)


    for ct in ct_pairs:
        y1 = ct[0]
        y2 = ct[1]
        pt = cryptosystem.decrypt(y1, y2)
        k = cryptosystem.discreteLog(y1)
        print("(" +numbersToText(pt)+ "," +str(k)+ ")")
