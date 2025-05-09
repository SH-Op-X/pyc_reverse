# pyinstaller-exe2py

我在学习pyc逆向过程中突发奇想，想实现直接从pyinstaller打包的exe转换为python脚本，因此有了这么一个小工具

本工具基于[pyinstxtractor-ng](https://github.com/pyinstxtractor/pyinstxtractor-ng)和[pycdc](https://github.com/zrax/pycdc/tree/master)，前者是一个不依赖python环境能够直接解包pyinstaller-exe的工具，后者是反编译pyc的工具。因此我将两者做了一个结合，运行工具加上exe目录能够直接提取exe里的入口python脚本，此外提供选项反编译import库pyc（建议需要时再加上此选项），更方便安全研究者和爱好者做CTF题或者分析exe

## Usage

目前工具只支持windows（因为我懒得跑linux编译pycdc了，直接用现成pycdc.exe了），和pyinstxtractor-ng一样使用了pyinstaller打包成了exe

~~~
positional arguments:
  filename       Path to the exe file to extract

optional arguments:
  -h, --help     show this help message and exit
  -i, --ex_import  Decompile import lib pyc. It is suggested to use this option only when you find that the import lib needed to be decompiled and analysed.
~~~

提取的python脚本直接放到了和exe同级目录下

## Todo

- [ ] 目前只能通过subprocess.run调用pycdc.exe，感觉很不规范，后续考虑把pycdc改编成python版本？可能会很复杂
- [ ] 修复未知编码bug，等待后续多测试（貌似代码里有中文可能会报编码错误）

欢迎issues，目前代码还很烂