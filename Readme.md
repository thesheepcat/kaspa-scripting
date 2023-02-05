## RedeemScript:

b.AddData(secret)
b.AddData(contract)


## plainredeemScript: 
 
b.AddData(secret)
c66531fb402f0088d9f5be954cbfededef83a9d3100ef028d57c5aef2dedba3a 

b.AddData(contract)
a820d87584e4523ea6597caa8fa9bf263a0456f525e59955fc7224a832c51053845e87


## PlainSecretContract to redeem: 

OP_SHA256
d87584e4523ea6597caa8fa9bf263a0456f525e59955fc7224a832c51053845e 
OP_EQUAL


## Operations sequence on the stack:
1. At first, script engine add on the stack all data from Redeem Script;
2. It adds on the stack the secret (stepping 00:0000: OP_DATA_32)
3. It adds on the stack the contract (stepping 00:0001: OP_DATA_35)
4. After adding all data from RedeemScript, script engine execute OP_BLAKE2B on the top element (the contract) and adds back the contract hash on the stack (stepping 01:0000: OP_BLAKE2B)
5. The script engine adds an additional dat on the stack (i expect it to be the hashed contract that's present in the locking script P2SH of the UTXO i'm trying to spend) (stepping 01:0001: OP_DATA_32); at that point, on the stack i can see the top 2 elements are equal;
6. The script engine execute OP_EQUAL to check if the two top elements of the stack are equal (stepping 01:0002: OP_EQUAL); they are equal and the script engine removes them from the stack;
7. The script engine elaborate the HASH SHA256 of the only item in the stack (the secret) and add the calculated hash back to the stack (stepping 02:0000: OP_SHA256);
8.  The script engine adds to the stack the secret hash include in the contract (stepping 02:0001: OP_DATA_32); at that point, on the stack i can see the top 2 elements are equal;
9.  The script enegine verifies the two secrets are equal and leave a 1 / true value on the stack (stepping 02:0002: OP_EQUAL);
10. The script has been successfully verified and the UTXO is spent.


