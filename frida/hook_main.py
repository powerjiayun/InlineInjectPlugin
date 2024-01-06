import os

import frida


def AirBuddy():
    launchApp(
        "/Applications/AirBuddy.app/Contents/MacOS/AirBuddy"
    )


def launchApp(image, js="_index.js"):
    pid = frida.spawn(image)
    frida.resume(pid)
    os.system(f"frida -p {pid} -l {js} --debug --runtime=v8")


if __name__ == '__main__':
    AirBuddy()