#!/usr/bin/env python3

import cmd
import errno
import getpass
import subprocess
import tomllib
from wakeonlan import send_magic_packet

def check_password(user, pw):
    # try to run 'true' as a given user to test her password
    cmd = (conf['binaries']['su'], '-c', conf['binaries']['true'], user)
    p = subprocess.run(cmd, 
                       input=f'{pw}\n', 
                       stdout=subprocess.PIPE,
                       encoding='utf-8')
    return True if p.returncode == 0 else False

def change_password(user, oldpw, newpw):
    cmd = (conf['binaries']['passwd'], user)
    p = subprocess.run(cmd, 
                       input=f'{oldpw}\n{newpw}\n{newpw}',
                       stdout=subprocess.PIPE,
                       encoding='utf-8')
    return True if p.returncode == 0 else False

class Wush(cmd.Cmd):
    prompt = '(wush) '
    intro = "Welcome to the WakeUp Shell.\n" \
        "Type 'help' or '?' to list available commands."

    def __init__(self, completekey='tab', stdin=None, stdout=None, config=None,
                 priviledged=False):
        super().__init__(completekey=completekey, stdin=stdin, stdout=stdout)
        self.config = config
        self.priviledged = priviledged
        self.current_user = getpass.getuser()

    def do_authorized(self, args):
        '''\
        List of authorized hosts for the current user, or the usernames given
        as arguments in the command line.'''
        # if no arguments were passed, use current username as argument
        usernames = [u.strip() for u in args.split()]
        if len(usernames) == 0:
            usernames = [self.current_user]
        for user in usernames:
            num_auth = 0
            result = ''
            # only list authorized hosts for other users if this is an 
            # priviledged instance
            if  user == self.current_user or \
                (user != self.current_user and self.priviledged):
                if user in self.config['users']:
                    candidates = self.config['users'][user]
                    hosts = [h for h in candidates if h in self.config['hosts']]
                    num_auth = len(hosts)
                    if num_auth > 0:
                        result = ' '.join(hosts)
                    else:
                        result = 'no authorized hosts found'
                if user not in self.config['users'] and self.priviledged:
                    result = 'unknown user'
            else:
                result = 'insufficient privileges'
            print(f'{user} ({num_auth}): {result}')

    def do_passwd(self, args):
        '''Change the current user password.'''
        current_pw = getpass.getpass(prompt=f'{self.prompt}current password: ')
        new_pw = getpass.getpass(prompt=f'{self.prompt}new password: ')
        retype_pw = getpass.getpass(prompt=f'{self.prompt}retype password: ')
        if new_pw != retype_pw:
            print(f"{self.prompt}passwords didn't match, not changing")
        else:
            print(f"{self.prompt}calling host system 'passwd'")
            change_password(self.current_user, current_pw, new_pw)
    
    def do_wakeup(self, args):
        '''Wakes up the given hosts using the Wake-On-LAN protocol.'''
        hostnames = [h.strip() for h in  args.split()]
        if len(hostnames) == 0:
            print('missing hostname')
            return
        user_hosts = self.config['users'][self.current_user]
        for host in hostnames:
            if (self.priviledged and host in self.config['hosts']) or \
              (not self.priviledged \
              and host in user_hosts \
              and host in self.config['hosts']):
                h = self.config['hosts'][host]
                try:
                    send_magic_packet(
                        h['mac_address'], interface=h['interface'])
                    print(f'{host}: magic packet sent')
                except OSError as e:
                    errdescr = errno.errorcode[e.errno]
                    print(f'{host}: error {errdescr}, no magic packet sent')
            else:
                print(f'{host}: unknown host')

    def do_whoami(self, args):
        '''Get the current username.'''
        print(self.current_user)

    def do_quit(self, args):
        '''Quits the current session.'''
        print(f'Bye {self.current_user}!')
        return True
    do_EOF = do_quit

if __name__ == '__main__':
    config_file = 'config.toml'

    with open(config_file, 'rb') as file:
        conf = tomllib.load(file)

    session = Wush(config=conf)

    if session.current_user not in session.config['users']:
        print(f'{session.current_user}: missing user configuration')
    else:
        session.cmdloop()