//
//  STTripleDES.m
//  MACPhone
//
//  Created by 云趣科技 on 2018/1/29.
//  Copyright © 2018年 suntek. All rights reserved.
//

#import "STTripleDES.h"

@implementation STTripleDES

#pragma mark - 加密解密
//加密
+ (NSString *)encryptUseDES:(NSString *)clearText key:(NSString *)key {
    
    NSData *data = [clearText dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
    
    size_t clearTextBufferSize = [data length];
    size_t numBytesEncrypted = 0;

    size_t bufferPtrSize = (clearTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    uint8_t *bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0, bufferPtrSize);
    
    const Byte iv[] = {0,0,0,0,0,0,0,0};
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithm3DES,
                                          kCCOptionPKCS7Padding,
                                          [key UTF8String],
                                          kCCKeySize3DES,
                                          iv,
                                          [data bytes],
                                          [data length],
                                          (void *)bufferPtr,
                                          bufferPtrSize,
                                          &numBytesEncrypted);

    NSString* plainText = nil;
    if (cryptStatus == kCCSuccess) {

        NSData *dataTemp = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)numBytesEncrypted];

        plainText = [STTripleDES byteToString:dataTemp];
        
        unsigned char *bytes = (unsigned char *)[dataTemp bytes];
        
        NSLog(@"加密以后的字节数组：%s", bytes);
        
    }else{
        NSLog(@"DES加密失败");
    }
    return plainText;
    
}

//解密
+ (NSString*)decryptUseDES:(NSString *)cipherText key:(NSString *)key {
    
    NSLog(@"转换前的string: %@", cipherText);
    NSData *cipherData = [STTripleDES stringToByte:cipherText];
    NSLog(@"转换后的data: %@", cipherData);
    
//    unsigned char bufferPtr[1024];
//    memset(bufferPtr, 0, sizeof(char));
    
    size_t cipherDataBufferSize = [cipherData length];
    
    size_t bufferPtrSize = (cipherDataBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    uint8_t *bufferPtr = malloc(bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0, bufferPtrSize);

    size_t numBytesDecrypted = 0;
    
    const Byte iv[] = {0,0,0,0,0,0,0,0};

    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithm3DES,
                                          kCCOptionPKCS7Padding,
                                          [key UTF8String],
                                          kCCKeySize3DES,
                                          iv,
                                          [cipherData bytes],
                                          [cipherData length],
                                          (void *)bufferPtr,
                                          bufferPtrSize,
                                          &numBytesDecrypted);
    NSString* plainText = nil;
    
    if (cryptStatus == kCCSuccess) {
        NSData *data = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)numBytesDecrypted];
        plainText = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    
    return plainText;
}

#pragma mark - 编码解码
//编码
+ (NSString *)byteToString:(NSData *)data {
    
    if (!data || [data length] == 0) {
        return @"";
    }
    
    NSMutableString *string = [[NSMutableString alloc] initWithCapacity:[data length]];
    
    [data enumerateByteRangesUsingBlock:^(const void * _Nonnull bytes, NSRange byteRange, BOOL * _Nonnull stop) {
        
        unsigned char *dataBytes = (unsigned char *)bytes;
        
        for (NSInteger i = 0; i < byteRange.length; i++) {
            
            NSString *hexStr = [NSString stringWithFormat:@"%x", (dataBytes[i]) & 0xff];
            
            if (hexStr.length == 2) {
                [string appendString:hexStr];
            } else {
                [string appendFormat:@"0%@", hexStr];
            }
        }
    }];
    
    return [string uppercaseString];
}

//解码
+ (NSData *)stringToByte:(NSString *)string {
    
    if (!string || [string length] == 0) {
        return nil;
    }
    
    NSMutableData *hexData = [[NSMutableData alloc] initWithCapacity:8];
    NSRange range;
    
    if ([string length] % 2 == 0) {
        range = NSMakeRange(0, 2);
    } else {
        range = NSMakeRange(0, 1);
    }

    for (NSInteger i = 0; i < [string length]; i += 2) {
        unsigned int anInt;
        NSString *hexCharStr = [string substringWithRange:range];
        
        NSScanner *scanner = [[NSScanner alloc] initWithString:hexCharStr];
        
        [scanner scanHexInt:&anInt];
        NSData *entity = [[NSData alloc] initWithBytes:&anInt length:1];
        
//        NSLog(@"字节: %d, data: %@", anInt, entity);
        
        [hexData appendData:entity];
        
        range.location += range.length;
        range.length = 2;
    }
    
    return hexData;
}

@end
