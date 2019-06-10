package com.company; 
2 
 
3 import javax.crypto.Cipher; 
4 import javax.crypto.Mac; 
5 import javax.crypto.spec.IvParameterSpec; 
6 import javax.crypto.spec.SecretKeySpec; 
7 import java.security.MessageDigest; 
8 import java.security.SecureRandom; 
9 
 
10 public class Main { 
11 
 
12     public static void main(String[] args) throws Exception { 
13         String key = "abcdefghijklmop"; 
14         String clean = "Quisque eget odio ac lectus vestibulum faucibus eget."; 
15          
16         byte[] encrypted = encrypt(clean, key); 
17         String decrypted = decrypt(encrypted, key); 
18     } 
19 
 
20     public static byte[] encrypt(String plainText, String key) throws Exception { 
21         byte[] clean = plainText.getBytes(); 
22 
 
23         // Generating IV. 
24         int ivSize = 16; 
25         byte[] iv = new byte[ivSize]; 
26         SecureRandom random = new SecureRandom(); 
27         random.nextBytes(iv); 
28         IvParameterSpec ivParameterSpec = new IvParameterSpec(iv); 
29 
 
30         // Hashing key. 
31         MessageDigest digest = MessageDigest.getInstance("SHA-256"); 
32         digest.update(key.getBytes("UTF-8")); 
33         byte[] keyBytes = new byte[16]; 
34         System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length); 
35         SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES"); 
36 
 
37         // Encrypt. 
38         Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); 
39         cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec); 
40         byte[] encrypted = cipher.doFinal(clean); 
41 
 
42         // Combine IV and encrypted part. 
43         byte[] encryptedIVAndText = new byte[ivSize + encrypted.length]; 
44         System.arraycopy(iv, 0, encryptedIVAndText, 0, ivSize); 
45         System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length); 
46 
 
47         return encryptedIVAndText; 
48     } 
49 
 
50     public static String decrypt(byte[] encryptedIvTextBytes, String key) throws Exception { 
51         int ivSize = 16; 
52         int keySize = 16; 
53 
 
54         // Extract IV. 
55         byte[] iv = new byte[ivSize]; 
56         System.arraycopy(encryptedIvTextBytes, 0, iv, 0, iv.length); 
57         IvParameterSpec ivParameterSpec = new IvParameterSpec(iv); 
58 
 
59         // Extract encrypted part. 
60         int encryptedSize = encryptedIvTextBytes.length - ivSize; 
61         byte[] encryptedBytes = new byte[encryptedSize]; 
62         System.arraycopy(encryptedIvTextBytes, ivSize, encryptedBytes, 0, encryptedSize); 
63 
 
64         // Hash key. 
65         byte[] keyBytes = new byte[keySize]; 
66         MessageDigest md = MessageDigest.getInstance("SHA-256"); 
67         md.update(key.getBytes()); 
68         System.arraycopy(md.digest(), 0, keyBytes, 0, keyBytes.length); 
69         SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES"); 
70 
 
71         // Decrypt. 
72         Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding"); 
73         cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec); 
74         byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes); 
75 
 
76         return new String(decrypted); 
77     } 
78 } 
