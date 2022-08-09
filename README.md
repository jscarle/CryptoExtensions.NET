# CryptoExtensions.NET - Useful Cryptography Extensions
A collection of four extensions using the current best practices for strong hashing and encryption.

[![MSBuild](https://github.com/jscarle/CryptoExtensions.NET/actions/workflows/msbuild.yml/badge.svg)](https://github.com/jscarle/CryptoExtensions.NET/actions/workflows/msbuild.yml)

## QuickStart
Be sure to first add the using statement
```csharp
using System.Security.Cryptography;
```

### Encrypting text
```csharp
var plainText = "Some text to encrypt";
var encryptedText = plainText.Encrypt("encryptionPassword");
```

### Decrypting text
```csharp
var encryptedText = "U29tZSB0ZXh0IHRvIGRlY3J5cHQ=";
var plainText = encryptedText.Decrypt("encryptionPassword");
```

### Hashing a password
```csharp
var password = "Some password to hash";
var passwordHash = password.Hash();
```

### Comparing a password hash
```csharp
var storedPasswordHash = "U29tZSBvdGhlciBwYXNzd29yZCBoYXNo";
var password = "Some password to compare";
var isValidPassword = password.CompareToHash(storedPasswordHash);
```
