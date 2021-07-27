from Crypto.PublicKey import RSA

fp = open("public.key" ,"r")
key = RSA.importKey(fp.read())
fp.close()

print("n: ", key.n)
print("e: ", key.e)
