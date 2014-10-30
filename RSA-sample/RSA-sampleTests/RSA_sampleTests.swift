//
//  RSA_sampleTests.swift
//  RSA-sampleTests
//
//  Created by ZERO on 14/10/25.
//  Copyright (c) 2014年 ZERO. All rights reserved.
//

import UIKit
import XCTest
import RSA_sample

class RSA_sampleTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testRSA() {
        // This is an example of a functional test case.
        let (puk, prk) = generateKeyPair()
        if puk == nil {
            return
        }
        let pukASN1 = encodePublicKeyForASN1(puk!)
        if pukASN1 == nil {
            return
        }
        let pukBase64 = pukASN1!.base64EncodedDataWithOptions(NSDataBase64EncodingOptions.allZeros)
        
        let data = [
            "account":"test10",
            "password":"a",
            "deviceId":"ffff",
            "game":"jxex",
            "key":NSString(data: pukBase64, encoding: NSASCIIStringEncoding)!
        ]
        let jsondata = NSJSONSerialization.dataWithJSONObject(data, options: nil, error: nil)!
        let (publicKey, privateKey) = generateKeyPair()
        let content = jsondata
        let cipher = encryptWithData(content, publicKey!)!
        let content2 = decryptWithData(cipher, privateKey!)!
        XCTAssert(content == content2, "Pass")
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock() {
            // Put the code you want to measure the time of here.
        }
    }
    
}
