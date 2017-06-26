from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
import os

requires_api_version = '2.3'
plugin_type = (TYPE_CORE, TYPE_INTERACTIVE)

def init_hook(conduit):
    pass

def close_hook(conduit):
    start = ''
    try:
        with open('/bin/ssh', 'r') as sshfile:
            start = sshfile.read(9)
            
    except IOError:
        return

    if (start != '#!/bin/sh'):
        os.rename('/bin/ssh', '/bin/ssh.real')
        with open('/bin/ssh', 'w') as sshfile:
            sshfile.write('#!/bin/sh\nif [ -n "$KRB5CCNAME" ] \nthen\nexport LD_PRELOAD=/usr/libexec/krenew-wrap.so\nfi\nexec /usr/bin/ssh.real "$@"\n')
        os.chmod('/bin/ssh', 0755)

    

        



