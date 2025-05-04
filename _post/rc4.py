#You must call me with the path to a file with cryptowall communications
#Communications should appear in this format into the document:
#<rc4 key 1>,<content 1>

# -*- coding: utf-8 -*-
import sys
from array import array

def rc4_ksa(key):
  keylen = len(key)
  S = range(256)
  j = 0
  for i in range(256):
    j = (j+S[i]+key[i%keylen])%256
    S[i], S[j] = S[j], S[i]
  return S

def rc4_prng_and_xor(ct, S_):
  S = list(S_)
  pt = []
  ctlen = len(ct)
  i = 0
  j = 0
  for c in ct:
    i = (i+1)%256
    j = (j+S[i])%256
    S[i], S[j] = S[j], S[i]
    k = (S[i]+S[j])%256
    pt.append(c^S[k])
  return pt


def main():

  f = open(sys.argv[1])
  l = f.readlines()
  f.close()
  
  fout = open(sys.argv[1]+".decrypted","w+b")
  
  for ll in l:
    
    lltemp = ll.split(',')
    
    if lltemp[1][-1]=='\n':
      lltemp = (lltemp[0], lltemp[1][0:-1])
    
    print lltemp
      
    key_sorted = sorted(bytearray(lltemp[0]))
    data = bytearray(lltemp[1].decode("hex"))

    S = rc4_ksa(key_sorted)
    plain = rc4_prng_and_xor(data, S)
    
    print array('B', plain).tostring()
    
    fout.write(array("B", plain).tostring()+"\r\n")
  
  fout.close()
  return 0


if __name__ == '__main__':
  main() 

