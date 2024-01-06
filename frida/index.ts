import {HookApp, log} from "./Utils.js";


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
        log("current:", tp.readInt())
        tp.writeInt(0)
        log("after:",tp,tp.readInt())
    })
})