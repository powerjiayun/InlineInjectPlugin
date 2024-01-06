export function log(...message: any): void {
    console.log(...message);
}

enum AccessType {
    Pointer,
    ObjectCFunction,
}

export type TargetFunction = {
    target: NativePointerValue,
    accessType: AccessType,
    msgTag: string//打印的日志标记
}

export type Tools = {
    watchMemory: (target: TargetFunction) => void;
}

export function HookApp(module: string, hookStart: (
    hook: (
        target: TargetFunction,
        leave: (
            ths: InvocationContext,
            retval: InvocationReturnValue
        ) => void,
        enter?: (
            ths: InvocationContext,
            args: InvocationArguments
        ) => void,
    ) => void,
    getPointer: (offsetMemmory: string | number | NativePointerValue | UInt64 | Int64) => TargetFunction,
    getClassMethod: (clazzName: string, clazzMethodSign: string) => TargetFunction,
    appBaseAddr: NativePointer,
    tools: Tools
) => void) {
    var appBaseAddr = Module.findBaseAddress(module)
    log(`App [${module}] 内存基址: ${appBaseAddr}`)
    let init = (appBaseAddr: NativePointer) => {
        let hook = (
            target: TargetFunction,
            leave: (ths: InvocationContext, retval: InvocationReturnValue) => void,
            enter?: (ths: InvocationContext, args: InvocationArguments) => void
        ) => {
            attachTarget(target, appBaseAddr, enter, leave, module)
        }
        hookStart(
            hook,
            (offsetMemmory: string | number | NativePointerValue | UInt64 | Int64) => {
                return {
                    target: appBaseAddr.add(offsetMemmory),
                    msgTag: "0x" + offsetMemmory.toString(16),
                    accessType: AccessType.Pointer
                }
            },
            (clazzName: string, clazzMethodSign: string) => {
                return {
                    target: ObjC.classes[clazzName][clazzMethodSign].implementation,
                    accessType: AccessType.ObjectCFunction,
                    msgTag: clazzName + " [" + clazzMethodSign + "]"
                }
            },
            appBaseAddr,
            {
                watchMemory: (target) => {
                    MemoryAccessMonitor.enable({
                        base: new NativePointer(target.target),
                        size: 16
                    }, {
                        onAccess: function (details) {
                            log("对内存[" + target.msgTag + "]访问来自", (details.from.sub(appBaseAddr)).toString())
                        }
                    })
                }
            }
        )
    }
    if (appBaseAddr != null) init(appBaseAddr)
}

function attachTarget(
    target: TargetFunction,
    appBaseAddr: NativePointer,
    enter?: (
        ths: InvocationContext,
        args: InvocationArguments
    ) => void,
    leave?: (
        ths: InvocationContext,
        retval: InvocationReturnValue
    ) => void,
    module?: string) {
    var line = "=".repeat(32);
    Interceptor.attach(target.target, {
        onEnter(this: InvocationContext, args: InvocationArguments) {
            log(line + ` \n${module} 进入函数 ` + target.msgTag + "\n")
            enter?.(this, args)
            log(line, "\n")
        },
        onLeave(retval) {
            log(line + ` \n${module} 退出函数 ` + target.msgTag + "\n")
            log("修改前返回值", retval)
            leave?.(this, retval)
            log("修改后返回值", retval, "\n" + line, "\n")
        },
    });
}