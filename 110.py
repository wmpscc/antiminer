import os
import subprocess
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
    status, cmd = subprocess.getstatusoutput('systemctl status ' + str(pid))
    if status != 0:
        return ''
    for i in cmd.split('\n'):
        if i.strip().startswith('CGroup'):
            session = i.split('/')[-1]
            return session.strip()


def check(p):
    if 'nbminer' in p.exe():
        return 1
    if p.cwd().startswith('/tmp/.dev'):  # 病毒伪装目录
        return 1
    if 'ethash' in p.cmdline():
        return 1
    if 'stratum' in p.cmdline():  # 以太坊矿池协议
        return 1
    if 'wallet' in p.cmdline():
        return 1
    if 'ssh' in p.cmdline() and '-f' in p.cmdline() and '-L' in p.cmdline() and '-N' in p.cmdline():  # 疑似内网端口映射
        return 1
    if '/tmp' in p.startswith():  # 问题文件常见目录
        return 2
    return 0


def do(p):
    code = check(p)
    if code == 0:
        return None
    sess = getSessionScope(p.pid)
    if code == 2:
        logging.warning('Suspicious file: session_scope: %s, cwd: %s, exe: %s' % (sess, p.cwd(), p.exe()))
    if code == 1:
        if sess != '':
            logging.error('Malicious file: session_scope: %s, cwd: %s, exe: %s' % (sess, p.cwd(), p.exe()))
            os.system('sudo systemctl kill -s SIGKILL ' + sess)
        else:
            p.kill()


def scan():
    for p in psutil.process_iter():
        try:
            do(p)
        except:
            pass

    logging.info('scan has completed')


if __name__ == '__main__':
    while True:
        scan()
        # 每5秒检测一次
        time.sleep(5)
