# -*- coding: UTF-8 -*-
import os
import commands
import psutil
import logging
import time

filename = os.path.split(os.path.realpath(__file__))[0] + '/scan.log'
logging.basicConfig(
    filename=filename,
    filemode='a+',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def getSessionScope(pid):
    status, cmd = commands.getstatusoutput('systemctl status ' + str(pid))
    if status != 0:
        return ''
    for i in cmd.split('\n'):
        if i.strip().startswith('CGroup'):
            session = i.split('/')[-1]
            user_slice = i.split('/')[-2]
            return user_slice.strip(), session.strip()


def check(p):
    cmdline = ''.join(p.cmdline())
    if 'nbminer' in p.exe():  # 开源挖矿程序
        return 1
    if p.cwd().startswith('/tmp/.dev'):  # 病毒伪装目录
        return 1
    if 'ethash' in cmdline:  # 以太坊
        return 1
    if 'stratum' in cmdline:  # 以太坊矿池协议
        return 1
    if 'wallet' in cmdline:  # 钱包地址
        return 1
    if 'ssh' in cmdline and '-f' in cmdline and '-L' in cmdline and '-N' in cmdline:  # 疑似内网端口映射
        return 1
    if p.cwd().startswith('/tmp'):  # 问题文件常见目录
        return 2
    return 0


def do(p):
    code = check(p)
    if code == 0:
        return None
    user, sess = getSessionScope(p.pid)
    if code == 2:
        logging.warning('Suspicious file: user slice: %s, session_scope: %s, cwd: %s, exe: %s, PID: %s' % (
            user, sess, p.cwd(), p.exe(), p.pid))
    if code == 1:
        if sess != '':
            logging.error(
                'Malicious file: user slice: %s, session_scope: %s, cwd: %s, exe: %s, PID: %s' % (
                    user, sess, p.cwd(), p.exe(), p.pid))
            os.system('sudo systemctl kill -s SIGKILL ' + sess)
        else:
            p.kill()


def scan():
    for p in psutil.process_iter():
        try:
            do(p)
        except Exception as e:
            logging.error(
                'Exception in program, please check.  cwd: %s, exe: %s, except: %s' % (p.cwd(), p.exe(), str(e)))


if __name__ == '__main__':
    print('running~')
    while True:
        scan()
        # 每5秒检测一次
        time.sleep(5)
