//
//  ViewController.m
//  fe
//
//  Created by iOS_Onion on 16/10/18.
//  Copyright © 2016年 iOS_Onion. All rights reserved.
//

#import "ViewController.h"

@interface ViewController ()<NSURLConnectionDelegate,NSURLConnectionDataDelegate>
@property (nonatomic,retain)NSMutableData *userData;

@end

@implementation ViewController


- (void)viewDidLoad {
    [super viewDidLoad];
    
    [self getDataWithuURLRequest];
    
}

- (void)getDataWithuURLRequest{
    NSString *urlStr = @"https://kyfw.12306.cn/otn/";
    NSURL *url = [NSURL URLWithString:urlStr];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url cachePolicy:NSURLRequestUseProtocolCachePolicy timeoutInterval:10];
    NSURLConnection *connection = [[NSURLConnection alloc]initWithRequest:request delegate:self];
    [connection start];
}

#pragma mark NSURLConnectionDelegate
- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace
{
    //表示是否对CA文件进行校验，YES就会调用didReceiveAuthenticationChallenge进行校验，NO:就是不进行校验
    NSString *authenticationMethodStr = protectionSpace.authenticationMethod;
    BOOL isServerTrust = [authenticationMethodStr isEqualToString:NSURLAuthenticationMethodServerTrust];
    
    return isServerTrust;
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    //对CA文件进行验证，并建立信任连接
    NSString *serverTrust = [[challenge protectionSpace] authenticationMethod];
    if ([serverTrust isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        //导入CA证书
        SecTrustRef serverTrust = [[challenge protectionSpace]serverTrust];
        NSString *cerPath = [[NSBundle mainBundle]pathForResource:@"srca" ofType:@"cer"];
        NSData *caCert = [NSData dataWithContentsOfFile:cerPath];
        if (nil == caCert)
        {
            return;
        }
        SecCertificateRef caRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)caCert);
        if (nil == caRef)
        {
            return;
        }
        NSArray *caArray = @[(__bridge id)caRef];
        OSStatus status = SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)caArray);
        if(!(errSecSuccess == status))
        {
            return;
        }
        SecTrustResultType result = -1;
        status = SecTrustEvaluate(serverTrust, &result);
        if (!(errSecSuccess == status))
        {
            return;
        }
        /**
         这里的关键在于result参数的值，根据官方文档的说明，判断(result == kSecTrustResultUnspecified) || (result == kSecTrustResultProceed)的值，若为1，则该网站的CA被app信任成功，可以建立数据连接，这意味着所有由该CA签发的各个服务器证书都被信任，而访问其它没有被信任的任何网站都会连接失败。该CA文件既可以是SLL也可以是自签名。
         */
        BOOL allowConnect = (result == kSecTrustResultUnspecified) || (result == kSecTrustResultProceed);
        if (allowConnect)
        {
            NSLog(@"success");
            [[challenge sender]useCredential:[NSURLCredential credentialForTrust:serverTrust] forAuthenticationChallenge:challenge];
        }else
        {
            NSLog(@"error");
        }
    }
}

- (void)connection:(NSURLConnection *)connection didCancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    NSLog(@"didCancelAuthenticationChallenge");
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    NSLog(@"didFailWithError");
}

#pragma mark NSURLConnectionDataDelegate
- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
    NSLog(@"didReciveResponse");
    _userData = [[NSMutableData alloc]init];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    NSLog(@"didReceiveData");
    [_userData appendData:data];;
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    NSString *receiveInfo = [NSJSONSerialization JSONObjectWithData:_userData options:NSJSONReadingAllowFragments error:nil];
    NSLog(@"receiveInfo:%@",receiveInfo);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
