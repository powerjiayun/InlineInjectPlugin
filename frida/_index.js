📦
839 /index.js.map
674 /index.js
2237 /Utils.js.map
2220 /Utils.js
✄
{"version":3,"file":"index.js","sourceRoot":"/Users/voidm/Documents/develop/workSpace/mac_hook/","sources":["index.ts"],"names":[],"mappings":"AAAA,OAAO,EAAC,OAAO,EAAE,GAAG,EAAC,MAAM,YAAY,CAAC;AAGxC,OAAO,CAAC,UAAU,EAAE,CAAC,IAAI,EAAE,UAAU,EAAE,cAAc,EAAE,WAAW,EAAE,KAAK,EAAE,EAAE;IACzE,IAAI,CAAC,UAAU,CAAC,OAAO,CAAC,EAAE,CAAC,GAAG,EAAE,GAAG,EAAE,EAAE;IAEvC,CAAC,EAAE,CAAC,GAAG,EAAE,IAAI,EAAE,EAAE;QACb,SAAS;QACT,wBAAwB;QACxB,yBAAyB;QACzB,mCAAmC;QACnC,8BAA8B;QAC9B,wBAAwB;QACxB,4BAA4B;QAC5B,MAAM;QACN,IAAI;QAEJ,IAAI,GAAG,GAAG,GAAG,CAAC,OAAO,CAAC,KAAK,CAAC,CAAC;QAC7B,IAAI,EAAE,GAAG,IAAI,aAAa,CAAC,GAAG,CAAC,CAAC,GAAG,CAAC,GAAG,CAAC,CAAC;QACzC,GAAG,CAAC,UAAU,EAAE,EAAE,CAAC,OAAO,EAAE,CAAC,CAAA;QAC7B,EAAE,CAAC,QAAQ,CAAC,CAAC,CAAC,CAAA;QACd,GAAG,CAAC,QAAQ,EAAC,EAAE,EAAC,EAAE,CAAC,OAAO,EAAE,CAAC,CAAA;IACjC,CAAC,CAAC,CAAA;AACN,CAAC,CAAC,CAAA"}
✄
import { HookApp, log } from "./Utils.js";
HookApp("AirBuddy", (hook, getPointer, getClassMethod, appBaseAddr, tools) => {
    hook(getPointer(0x50480), (ths, rev) => {
    }, (ths, args) => {
        // 打印堆栈信息
        // let obj = ths.context
        // for (let key in obj) {
        //   if (obj.hasOwnProperty(key)) {
        //     const value = obj[key];
        //     log("Key:", key);
        //     log("Value:", value);
        //   }
        // }
        let r13 = ths.context["r13"];
        let tp = new NativePointer(r13).add(153);
        log("current:", tp.readInt());
        tp.writeInt(0);
        log("after:", tp, tp.readInt());
    });
});
✄
{"version":3,"file":"Utils.js","sourceRoot":"/Users/voidm/Documents/develop/workSpace/mac_hook/","sources":["Utils.ts"],"names":[],"mappings":"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"}
✄
export function log(...message) {
    console.log(...message);
}
var AccessType;
(function (AccessType) {
    AccessType[AccessType["Pointer"] = 0] = "Pointer";
    AccessType[AccessType["ObjectCFunction"] = 1] = "ObjectCFunction";
})(AccessType || (AccessType = {}));
export function HookApp(module, hookStart) {
    var appBaseAddr = Module.findBaseAddress(module);
    log(`App [${module}] 内存基址: ${appBaseAddr}`);
    let init = (appBaseAddr) => {
        let hook = (target, leave, enter) => {
            attachTarget(target, appBaseAddr, enter, leave, module);
        };
        hookStart(hook, (offsetMemmory) => {
            return {
                target: appBaseAddr.add(offsetMemmory),
                msgTag: "0x" + offsetMemmory.toString(16),
                accessType: AccessType.Pointer
            };
        }, (clazzName, clazzMethodSign) => {
            return {
                target: ObjC.classes[clazzName][clazzMethodSign].implementation,
                accessType: AccessType.ObjectCFunction,
                msgTag: clazzName + " [" + clazzMethodSign + "]"
            };
        }, appBaseAddr, {
            watchMemory: (target) => {
                MemoryAccessMonitor.enable({
                    base: new NativePointer(target.target),
                    size: 16
                }, {
                    onAccess: function (details) {
                        log("对内存[" + target.msgTag + "]访问来自", (details.from.sub(appBaseAddr)).toString());
                    }
                });
            }
        });
    };
    if (appBaseAddr != null)
        init(appBaseAddr);
}
function attachTarget(target, appBaseAddr, enter, leave, module) {
    var line = "=".repeat(32);
    Interceptor.attach(target.target, {
        onEnter(args) {
            log(line + ` \n${module} 进入函数 ` + target.msgTag + "\n");
            enter?.(this, args);
            log(line, "\n");
        },
        onLeave(retval) {
            log(line + ` \n${module} 退出函数 ` + target.msgTag + "\n");
            log("修改前返回值", retval);
            leave?.(this, retval);
            log("修改后返回值", retval, "\n" + line, "\n");
        },
    });
}