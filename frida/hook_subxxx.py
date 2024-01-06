# frida-ps | grep Air
# 89986  AirBuddy

import sys
import frida


def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Hooked function:", message,data)
    else:
        print("[-] Error:", message,data)


script_code_v2 = '''function get_func_addr(module, offset) {

    var base_addr = Module.findBaseAddress(module);
    console.log("base_addr: " + base_addr);

    var func_addr = base_addr.add(offset);
    if (Process.arch === 'arm')
        return func_addr.add(1);  //如果是32位地址+1
    else
        return func_addr;
}

var func_addr = get_func_addr('AirBuddy', 0x50480);

console.log('func_addr: ' + func_addr);
console.log('ptr(func_addr): ' + ptr(func_addr));
console.log('hexdump(ptr(func_addr): ' + hexdump(ptr(func_addr), {
    length: 16,
    header: true,
    ansi: true
}));


Interceptor.attach(ptr(func_addr), {
    onEnter: function (args) {

        console.log("onEnter");
        var num1 = args[0];
        console.log("	[>>] num1: " + num1);

        let r13 = this.context["r13"];
        let tp = new NativePointer(r13).add(153);
        console.log("	[>>] tp current: " + tp.readInt());
        tp.writeInt(0);
        console.log("	[>>] tp after: " + tp.readInt());
        // 消息发送给 python
        // send(tp)
    },
    onLeave: function (retval) {

        console.log("onLeave");

        console.log("	[<<] Type of return value: " + typeof retval);
        console.log("	[<<] Original Return Value: " + retval);
        // retval.replace(0);  //将返回值替换成0
        console.log("	[<<] New Return Value: " + retval);
    }
});

'''

pid = frida.spawn(["/Applications/AirBuddy.app/Contents/MacOS/AirBuddy"])
frida.resume(pid)
session = frida.attach(pid)

# 创建并注入JavaScript脚本
script = session.create_script(script_code_v2)
script.on('message', on_message)
script.load()
sys.stdin.read()

# python3 hook.py

if __name__ == '__main__':
    pass
