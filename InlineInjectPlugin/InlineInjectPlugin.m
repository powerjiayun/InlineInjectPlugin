//
//  InlineInjectPlugin.m
//  InlineInjectPlugin
//
//  Created by 马治武 on 2024/1/6.
//

#import "InlineInjectPlugin.h"
#import "Utils.h"
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <SwiftUI/SwiftUI.h>
#import "rd_route.h"
#import <Cocoa/Cocoa.h>

@implementation InlineInjectPlugin



int (*_0x100050480Ori)();

int _0x100050480New() {
    // register int r13 asm("r13"); //读取寄存器的值
    NSLog(@"==== _0x100050480New called");
    // *(*r13 + 153) = 0;
    __asm
    {
        //内联汇编直接修改寄存器的值
        mov byte ptr[r13+99h], 0
    }
    NSLog(@"==== _0x100050480New call end");
    return _0x100050480Ori(); // 调用原函数恢复执行
}

void AirBuddy(){
     if (!checkSelfInject("codes.rambo.AirBuddy")) return;
    //    register int i asm("r13");
    //    Method activated = class_getInstanceMethod(NSClassFromString(@"PADProduct"), NSSelectorFromString(@"activated"));
    //    Method activatedEx = class_getInstanceMethod([InlineInjectPlugin class], @selector(activated));
    //    method_exchangeImplementations(activated, activatedEx);
        
    
    intptr_t _0x100050480 = _dyld_get_image_vmaddr_slide(0) + 0x100050480;
    rd_route((void *) _0x100050480, _0x100050480New, (void **) &_0x100050480Ori);
}


+ (void) load {
    NSString *appName = [[NSBundle mainBundle] bundleIdentifier];
    const char *myAppBundleName = [appName UTF8String];
    NSLog(@"=== AppName is %s.",myAppBundleName);
    
    NSAlert *alert = [[NSAlert alloc] init];
        [alert setMessageText:@"确认执行破解操作吗？"];
        [alert addButtonWithTitle:@"确认"];
        [alert addButtonWithTitle:@"取消"];
        
    NSInteger response = [alert runModal];
    if (response == NSAlertFirstButtonReturn) {
        // 用户选择了确认按钮
        AirBuddy();
    } else {
        // 用户选择了取消按钮
        return;
    }
    
    
}


@end
