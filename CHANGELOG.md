# Exodus seedphrase decryptor

## 🆕 Changelog

### v4.0.0 
- **secure-container API missmatch** :  Fixed the previous secure-container version issues where they have updated old - **Synchronous decryptData() / encryptData()**  with new -  **Asynchronous decrypt() / encrypt()** returning an object with **.data**
- Using the old synchronous API in modern versions throws "```secureContainer.decryptData is not a function```".
  
