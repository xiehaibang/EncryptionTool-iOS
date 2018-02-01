//
//  STTripleDES.h
//  MACPhone
//
//  Created by 云趣科技 on 2018/1/29.
//  Copyright © 2018年 suntek. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

@interface STTripleDES : NSObject

/**
 3DES 加密

 @param clearText 要加密的明文
 @param key 加密密匙
 @return 加密后的密文
 */
+ (NSString *)encryptUseDES:(NSString *)clearText key:(NSString *)key;

/**
 3DES 解密

 @param cipherText 要解密的密文
 @param key 解密密匙
 @return 解密后的明文
 */
+ (NSString*)decryptUseDES:(NSString *)cipherText key:(NSString *)key;


@end
