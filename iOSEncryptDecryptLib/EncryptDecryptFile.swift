//
//  EncryptDecryptFile.swift
//  iOSEncryptDecryptLib
//
//  Created by Prajakta Kiran Patil on 16/07/22.
//

import Foundation
import CommonCrypto
import CryptoKit


//-------- For Cryptokit-----------

public class CryptoKitClass {

    var passowrdString: String!
    let randomKey = SymmetricKey(size: .bits256)
    
    public init(passowrdString: String) {
            self.passowrdString = passowrdString
    }
    
    public func encryptFunc() throws -> String {
        let textData = passowrdString.data(using: .utf8)!
        let encrypted = try AES.GCM.seal(textData, using: randomKey)
        return encrypted.combined!.base64EncodedString()
    }

    public func decryptFunc() -> String {
        do {
            guard let data = Data(base64Encoded: try encryptFunc()) else {
                return "Could not decode text: \(passowrdString ?? "")"
            }

            let sealedBox = try AES.GCM.SealedBox(combined: data)
            let decryptedData = try AES.GCM.open(sealedBox, using: randomKey)

            guard let text = String(data: decryptedData, encoding: .utf8) else {
                return "Could not decode data: \(decryptedData)"
            }

            return text
        } catch let error {
            return "Error decrypting message: \(error.localizedDescription)"
        }
    }
    
    
/*------------------AUTHENTICATE---------------------------

--------------- Hash-based Message Authentication Code
--------------- The HMAC process mixes a secret key with the message data and hashes the result. The hash value is mixed with the secret key again, and then hashed a second time.

------------------AUTHENTICATE---------------------------*/


        // CrytoKit
        public func hashHmacSHA512CryptoKit() -> String? {
            // Create the hash
            let passwordData = passowrdString.data(using: .utf8)!
            let symmetricKey = SymmetricKey(data: passwordData)
            let passwordHashDigest = HMAC<SHA512>.authenticationCode(for: passwordData, using: symmetricKey)
            return formatPassword(Data(passwordHashDigest))
        }

/*----------------------HASHING-----------------------------
 
--------------- Hashing algorithm used to convert text of any length into a fixed-size string.
--------------- Each output produces a SHA-512 length of 512 bits (64 bytes). This algorithm is commonly used for email addresses hashing, password hashing, and digital record verification.
 
----------------------HASHING-----------------------------*/


        // CrytoKit
        public func hashSha512CryptoKit() -> String? {
            // Create the hash
            let passwordData = passowrdString.data(using: .utf8)!
            let passwordHashDigest = SHA512.hash(data: passwordData)
            return formatPassword(Data(passwordHashDigest))
        }

        // Common Password Format
        func formatPassword(_ password: Data) -> String {
            var passwordString : String = password.map { String(format: "%02x", $0) }.joined()
            // Add a dash after every 8 characters
            var index = passwordString.index(passwordString.startIndex, offsetBy: 8)
            repeat {
                passwordString.insert("-", at: index)
                passwordString.formIndex(&index, offsetBy: 9)
            } while index < passwordString.endIndex
            return passwordString
        }
    
    
}


// -------- For Common Crypto -----------


protocol Cryptable {
    func encrypt(_ string: String) throws -> Data
    func decrypt(_ data: Data) throws -> String
}

public class CommonCryptoKitClass : Cryptable {

     private let key: Data
     private let ivSize: Int         = kCCBlockSizeAES128
     private let options: CCOptions  = CCOptions(kCCOptionPKCS7Padding)

    public init(keyString: String) throws {
        guard keyString.count == kCCKeySizeAES256 else {
            throw Error.invalidKeySize
        }
        self.key = Data(keyString.utf8)
    }
    
// CommonCrypto
//    public func hashSha512CommonCrypto() -> String? {
//        // Create the password hash
//        var digest = Data(count: Int(CC_SHA512_DIGEST_LENGTH))
//        digest.withUnsafeMutableBytes {mutableBytes in
//            CC_SHA512(passowrdString, CC_LONG(passowrdString.utf8.count), mutableBytes.bindMemory(to: UInt8.self).baseAddress)
//        }
//        return formatPassword(digest)
//    }
//
//
//    public func hashHmacSHA512CommonCrypto() -> String? {
//        // Create the password hash
//        var digest = Data(count: Int(CC_SHA512_DIGEST_LENGTH))
//        digest.withUnsafeMutableBytes {mutableBytes in
//            CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA512), passowrdString, passowrdString.utf8.count, passowrdString, passowrdString.utf8.count, mutableBytes.baseAddress)
//        }
//        return formatPassword(digest)
//    }
    
   public func encrypt(_ string: String) throws -> Data {
       let dataToEncrypt = Data(string.utf8)

       let bufferSize: Int = ivSize + dataToEncrypt.count + kCCBlockSizeAES128
       var buffer = Data(count: bufferSize)
       try generateRandomIV(for: &buffer)

       var numberBytesEncrypted: Int = 0

       do {
           try key.withUnsafeBytes { keyBytes in
               try dataToEncrypt.withUnsafeBytes { dataToEncryptBytes in
                   try buffer.withUnsafeMutableBytes { bufferBytes in

                       guard let keyBytesBaseAddress = keyBytes.baseAddress,
                           let dataToEncryptBytesBaseAddress = dataToEncryptBytes.baseAddress,
                           let bufferBytesBaseAddress = bufferBytes.baseAddress else {
                               throw Error.encryptionFailed
                       }

                       let cryptStatus: CCCryptorStatus = CCCrypt( // Stateless, one-shot encrypt operation
                           CCOperation(kCCEncrypt),                // op: CCOperation
                           CCAlgorithm(kCCAlgorithmAES),           // alg: CCAlgorithm
                           options,                                // options: CCOptions
                           keyBytesBaseAddress,                    // key: the "password"
                           key.count,                              // keyLength: the "password" size
                           bufferBytesBaseAddress,                 // iv: Initialization Vector
                           dataToEncryptBytesBaseAddress,          // dataIn: Data to encrypt bytes
                           dataToEncryptBytes.count,               // dataInLength: Data to encrypt size
                           bufferBytesBaseAddress + ivSize,        // dataOut: encrypted Data buffer
                           bufferSize,                             // dataOutAvailable: encrypted Data buffer size
                           &numberBytesEncrypted                   // dataOutMoved: the number of bytes written
                       )

                       guard cryptStatus == CCCryptorStatus(kCCSuccess) else {
                           throw Error.encryptionFailed
                       }
                   }
               }
           }

       } catch {
           throw Error.encryptionFailed
       }

       let encryptedData: Data = buffer[..<(numberBytesEncrypted + ivSize)]
       return encryptedData
   }

   public func decrypt(_ data: Data) throws -> String {

       let bufferSize: Int = data.count - ivSize
       var buffer = Data(count: bufferSize)

       var numberBytesDecrypted: Int = 0

       do {
           try key.withUnsafeBytes { keyBytes in
               try data.withUnsafeBytes { dataToDecryptBytes in
                   try buffer.withUnsafeMutableBytes { bufferBytes in

                       guard let keyBytesBaseAddress = keyBytes.baseAddress,
                           let dataToDecryptBytesBaseAddress = dataToDecryptBytes.baseAddress,
                           let bufferBytesBaseAddress = bufferBytes.baseAddress else {
                               throw Error.encryptionFailed
                       }

                       let cryptStatus: CCCryptorStatus = CCCrypt( // Stateless, one-shot encrypt operation
                           CCOperation(kCCDecrypt),                // op: CCOperation
                           CCAlgorithm(kCCAlgorithmAES128),        // alg: CCAlgorithm
                           options,                                // options: CCOptions
                           keyBytesBaseAddress,                    // key: the "password"
                           key.count,                              // keyLength: the "password" size
                           dataToDecryptBytesBaseAddress,          // iv: Initialization Vector
                           dataToDecryptBytesBaseAddress + ivSize, // dataIn: Data to decrypt bytes
                           bufferSize,                             // dataInLength: Data to decrypt size
                           bufferBytesBaseAddress,                 // dataOut: decrypted Data buffer
                           bufferSize,                             // dataOutAvailable: decrypted Data buffer size
                           &numberBytesDecrypted                   // dataOutMoved: the number of bytes written
                       )

                       guard cryptStatus == CCCryptorStatus(kCCSuccess) else {
                           throw Error.decryptionFailed
                       }
                   }
               }
           }
       } catch {
           throw Error.encryptionFailed
       }

       let decryptedData: Data = buffer[..<numberBytesDecrypted]

       guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
           throw Error.dataToStringFailed
       }

       return decryptedString
   }

}

extension CommonCryptoKitClass {
    enum Error: Swift.Error {
        case invalidKeySize
        case generateRandomIVFailed
        case encryptionFailed
        case decryptionFailed
        case dataToStringFailed
    }
}

private extension CommonCryptoKitClass {

    func generateRandomIV(for data: inout Data) throws {

        try data.withUnsafeMutableBytes { dataBytes in

            guard let dataBytesBaseAddress = dataBytes.baseAddress else {
                throw Error.generateRandomIVFailed
            }

            let status: Int32 = SecRandomCopyBytes(
                kSecRandomDefault,
                kCCBlockSizeAES128,
                dataBytesBaseAddress
            )

            guard status == 0 else {
                throw Error.generateRandomIVFailed
            }
        }
    }
}


