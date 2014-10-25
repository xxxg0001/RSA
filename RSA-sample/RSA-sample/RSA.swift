//
//  RSA.swift
//  RSA-sample
//
//  Created by ZERO on 14/10/25.
//  Copyright (c) 2014年 ZERO. All rights reserved.
//

import Foundation


let publicTag = "com.xxxg0001.RSA-sample.publicKey".dataUsingEncoding(String.defaultCStringEncoding(), allowLossyConversion: false)!
let privateTag = "com.xxxg0001.RSA-sample.privateKey".dataUsingEncoding(String.defaultCStringEncoding(), allowLossyConversion: false)!

let kSecPrivateKeyAttrsValue = kSecPrivateKeyAttrs.takeUnretainedValue() as NSCopying
let kSecPublicKeyAttrsValue = kSecPublicKeyAttrs.takeUnretainedValue() as NSCopying

public func loadDER() -> SecKeyRef? {
    let file = NSBundle.mainBundle().pathForResource("public_key", ofType: "der")
    if file == nil {
        println("no file")
        return nil
    }
    
    let publicKeyFileContent: AnyObject? = NSData(contentsOfFile: file!)
    if publicKeyFileContent == nil{
        println("Can not read from pub.der")
        return nil
    }
    let certificate = SecCertificateCreateWithData(kCFAllocatorDefault, publicKeyFileContent  as CFData).takeUnretainedValue()
    let policy = SecPolicyCreateBasicX509().takeUnretainedValue();
    var unmanagedTrust : Unmanaged<SecTrust>? = nil
    let status = SecTrustCreateWithCertificates(certificate, policy, &unmanagedTrust)
    if (status != 0) {
        println("SecTrustCreateWithCertificates fail. Error Code: \(status)");
        return nil
    }
    let trust = unmanagedTrust!.takeUnretainedValue()
    let evaluateStatus = SecTrustEvaluate(trust, nil)
    if (evaluateStatus != 0) {
        println("SecTrustEvaluate fail. Error Code: \(evaluateStatus)");
        return nil
    }
    return SecTrustCopyPublicKey(trust).takeUnretainedValue();
}

public func generateKeyPair() ->(SecKeyRef?, SecKeyRef?) {
    let privateKeyAttr = NSMutableDictionary()
    let publicKeyAttr = NSMutableDictionary()
    let keyPairAttr = NSMutableDictionary()
    
    let size :CFNumberRef = 1024
    let NYES = NSNumber(bool: true)
    keyPairAttr.setValue(kSecAttrKeyTypeRSA, forKey: kSecAttrKeyType)
    keyPairAttr.setValue(size, forKey: kSecAttrKeySizeInBits)
    
    privateKeyAttr.setValue(NYES, forKey: kSecAttrIsPermanent)
    privateKeyAttr.setValue(privateTag, forKey: kSecAttrApplicationTag)
    publicKeyAttr.setValue(NYES, forKey: kSecAttrIsPermanent)
    publicKeyAttr.setValue(publicTag, forKey: kSecAttrApplicationTag)
    keyPairAttr.setObject(privateKeyAttr, forKey: kSecPrivateKeyAttrsValue)
    keyPairAttr.setObject(publicKeyAttr, forKey: kSecPublicKeyAttrsValue)
    
    var publicKey : Unmanaged<SecKey>?
    var privateKey : Unmanaged<SecKey>?
    
    let status = SecKeyGeneratePair(keyPairAttr as CFDictionaryRef, &publicKey, &privateKey)
    if status != 0 {
        println("generateKeyPair fail, Error Code:\(status)")
        return (nil, nil)
    }
    return (publicKey!.takeUnretainedValue(), privateKey!.takeUnretainedValue())
}

public func decryptWithData(cipher :NSData, privateKey :SecKeyRef) -> NSData? {
    var contentLen = SecKeyGetBlockSize(privateKey)
    var content = [UInt8](count: Int(contentLen), repeatedValue: 0)
    let status = SecKeyDecrypt(privateKey, SecPadding(kSecPaddingPKCS1), UnsafePointer<UInt8>(cipher.bytes), UInt(cipher.length), &content, &contentLen)
    if status != 0 {
        println("SecKeyDecrypt fail, Error Code: \(status)")
        return nil
    }
    return NSData(bytes: content, length: Int(contentLen))
    
}

public func encryptWithData(content :NSData, publicKey :SecKeyRef) -> NSData? {
    var cipherLen = SecKeyGetBlockSize(publicKey)
    let maxPlainLen = Int(cipherLen - 12);
    if (content.length > maxPlainLen) {
        println("content(\(content.length)) is too long, must < \(maxPlainLen)")
        return nil
    }
    var cipher = [UInt8](count: 128*sizeof(UInt8), repeatedValue: 0)
    let status = SecKeyEncrypt(publicKey, SecPadding(kSecPaddingPKCS1), UnsafePointer<UInt8>(content.bytes), UInt(content.length), &cipher, &cipherLen)
    if status != 0 {
        println("SecKeyEncrypt fail. Error Code: \(status)")
        return nil
    }
    return NSData(bytes: cipher, length: Int(cipherLen))
}

func getPublicKeyBits(publicKey: SecKeyRef) -> NSData? {
    let queryPublicKey = NSMutableDictionary()
    queryPublicKey.setValue(kSecClassKey, forKey: kSecClass)
    queryPublicKey.setValue(publicTag, forKey: kSecAttrApplicationTag)
    queryPublicKey.setValue(kSecAttrKeyTypeRSA, forKey: kSecAttrKeyType)
    SecItemDelete(queryPublicKey)
    queryPublicKey.setValue(publicKey, forKey: kSecValueRef)
    queryPublicKey.setValue(NSNumber(bool: true), forKey: kSecReturnData)
    var publicKeyBits:Unmanaged<AnyObject>?
    let status = SecItemAdd(queryPublicKey, &publicKeyBits)
    if status != 0 {
        println("getPublicKeyRef fail. Error Code:\(status)")
        return nil
    }
    return publicKeyBits!.takeUnretainedValue() as? NSData
}

func encodeLength(inout data:[UInt8], offset:Int, count:Int) -> Int {
    var length = count
    if (length < 128) {
        data[offset] = UInt8(length)
        return 1
    }
    let i = UInt((length / 256) + 1)
    data[offset] = UInt8(i + 0x80)
    for j in 0..<i {
        data[i-j+offset] = UInt8(length & 0xFF)
        length = length >> 8
    }
    return Int(i + 1)
}

public func encodePublicKeyForASN1(publicKey:SecKeyRef) -> NSData? {
    if let publicKeyBits = getPublicKeyBits(publicKey) {
        let _encodeRSAEncryptionOID:[UInt8] = [
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
        ]
        var builder = [UInt8](count: 15, repeatedValue: 0)
        let encKey = NSMutableData()
        var bitstringEncLength = 0
        if publicKeyBits.length + 1 < 128 {
            bitstringEncLength = 1
        } else {
            bitstringEncLength = Int(((publicKeyBits.length + 1)/256) + 2)
        }
        builder[0] = UInt8(0x30)
        var i :Int = Int(_encodeRSAEncryptionOID.count + 2 + bitstringEncLength + publicKeyBits.length)
        var j = encodeLength(&builder, 1, i)
        encKey.appendBytes(builder, length: j+1)
        encKey.appendBytes(_encodeRSAEncryptionOID, length: _encodeRSAEncryptionOID.count)
        builder[0] = 0x03
        j = encodeLength(&builder, 1, publicKeyBits.length + 1)
        builder[j+1] = 0x00
        encKey.appendBytes(builder, length: j+2)
        encKey.appendData(publicKeyBits)
        return encKey
    }
    return nil
}



