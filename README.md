# DES-Java
A Java class designed to perform DES encryption on files.

Use of this class is as follows:

Setting the DES cipher master key: `des.setKey( long );`.

Performing encryption: `des.encrypt(FileInputStream, FileOutputStream);`.

Performing decryption: `des.decrypt(FileInputStream, FileOutputStream);`.


An example application is as follows:
```
DES des = new DES();
des.setKey(0b0110110001101100001111000011001100111100001001111001110001101010L);

FileInputStream inputstream = new FileInputStream("plaintext.txt");
FileOutputStream outputstream = new FileOutputStream("ciphertext.txt");
			
des.encrypt(inputstream, outputstream);
```


![UML](https://github.com/Meandi-n/DES-Java/blob/main/DES_UML.drawio.png)
