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
        let (publicKey, privateKey) = generateKeyPair()
        let content = "test message".dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)!
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
