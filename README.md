# Anti-miner
该脚本按条件筛选出疑似挖矿病毒的进程。

ps: 系统多个文件被替换为带毒文件，不易修复又不能重装系统下使用。

## 规则
- 请按照系统中挖矿病毒的特点，修改 **check()** 函数。
- 检测到疑似挖矿进程会直接KILL掉进程所属用户的相应Session scope。
- 日志文件存储在运行目录`scan.log`

```python
def check(p):
    if 'nbminer' in p.exe():
        return 1
    if p.cwd().startswith('/tmp/.dev'):
        return 1
    ...
```

## 运行
目录下`install-*.sh`脚本安装python的`psutil`包。

看脚本后缀，使用对应python版本运行

```shell
sudo python 110py2.py # python2.x
sudo python 110py3.py # python3.x
```

**注意：python2运行py3无效，python3无法运行py2！！！一定要对应版本运行**

## 参考
- [https://github.com/bojone/antiminer](https://github.com/bojone/antiminer)

