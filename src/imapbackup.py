import imapclient
import bz2

import os

import pickle

import re

import hashlib

import sqlite3

import tzlocal
import email

import backports

import time

import logging
import logging.handlers
import logging.config

log = logging.getLogger(__name__)


def get_message_id(data):
    m = re.search(br'^[^<]+<([^>]+)>', data[b'BODY[HEADER.FIELDS (MESSAGE-ID)]'], re.MULTILINE)
    if m is not None:
        message_id = m.group(1).decode()
    else:
        uk = data[b'BODY[HEADER]']
        message_id = 'UUID.%s' % hashlib.sha256(uk).hexdigest()
        
    return message_id
    
def fetch_chunk(M, uid_list, params, chunk_size=5):
    chunks = [uid_list[x:x+chunk_size] for x in range(0, len(uid_list), chunk_size)]

    messages = {}
    for i, chunk in enumerate(chunks, 1):
        log.debug("- Reading chunk %i/%i..." % (i, len(chunks)))
        message = M.fetch(chunk, params)
        messages.update(message)
        
        
    return messages
    
def split_chunks(uid_list, chunk_size=5):
    return [uid_list[x:x+chunk_size] for x in range(0, len(uid_list), chunk_size)]

def split_chunks_by_size(M, uid_list, max_chunk_size_mb=5):
    log.debug("Fetching message sizes...")
    msgs = M.fetch(uid_list, ['RFC822.SIZE'])
    msgs_lt = [(uid, v[b'RFC822.SIZE']) for uid, v in msgs.items()]
    msgs_lt.sort(key=lambda x: x[1])

    max_chunk_size_bytes = max_chunk_size_mb*1024*1024

    groups = []
    group = []
    acum = 0
    for uid, size in msgs_lt:
        if acum + size > max_chunk_size_bytes:
            groups.append((group, acum))
            group = [uid]
            acum = size
        else:
            group.append(uid)
            acum += size

    if group != []:
        groups.append((group, acum))

    return groups
    
    
#######################################3

class store_db:
    def __init__(self, filename):
        new_db = not os.path.isfile(filename)
    
        self.conn = sqlite3.connect(filename)
        self.c = self.conn.cursor()

        if new_db:
            log.debug("* Database not exists. Creating...")

            self.c.execute('''CREATE TABLE mailbox
                         (id integer primary key, 
                          name text not null unique,
                          subscribed integer not null
                         )''')
          
            self.c.execute('''CREATE TABLE message
                         (id integer primary key, 
                          message_id blob not null,
                          message blob not null,
                          mailbox_id integer not null,
                          FOREIGN KEY(mailbox_id) REFERENCES mailbox(id)
                         )''')
                         
            self.c.execute('''CREATE UNIQUE INDEX "message_mailbox" on message (mailbox_id, message_id)''')
            
            self.conn.commit()

    def create_mailbox(self, mailbox, subscribed=False):
        exists = False
        try:
            self.c.execute("INSERT INTO mailbox(name, subscribed) VALUES (?, ?)", (mailbox, subscribed))
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            exists = True
            
        return exists

    def sha512(self, to_file=None):
        m = hashlib.sha512()

        for t in self.c.execute("select name, subscribed from mailbox order by name"):
            m.update(pickle.dumps(t, pickle.HIGHEST_PROTOCOL))

        for t in self.c.execute("select message_id from message order by message_id"):
            m.update(pickle.dumps(t, pickle.HIGHEST_PROTOCOL))

        d = m.hexdigest()
        if to_file is not None:
            with open(to_file, 'w') as f:
                f.write(d)

        return d

            
    def logout(self):
        #log.debug("Vacuum database...")
        #self.conn.execute('VACUUM')
        # We can also close the connection if we are done with it.
        # Just be sure any changes have been committed or they will be lost.
        self.conn.close()


class store_imap:
    def __init__(self, host, username, password, ssl=False):
        self.M = patchedIMAPClient(host, use_uid=True, ssl=ssl)

        self.M.login(username, password)

    def create_mailbox(self, mailbox, subscribed=False):
        f_l = mailbox.split('.')
        n = len(f_l)
        exists = True
        for i in range(n):
            subf = '.'.join(f_l[0:i + 1])
            if not self.M.folder_exists(subf):
                self.M.create_folder(subf)
                exists = False

            if subscribed:
                self.M.subscribe_folder(subf)
            else:
                self.M.unsubscribe_folder(subf)

        return n > 0 and exists

    def logout(self):
        self.M.logout()

def sslpatch(func):
    def func_wrapper(self, *args, **kwargs):
        N = 100
        for i in range(1, N + 1):
            try:
                return func(self, *args, **kwargs)
                break
            except backports.ssl.core.SSLSysCallError as e:
                log.debug('************ Bug error: %s Trying again %i/%i... ******************' % (e, i, N))
                if i >= N:
                    raise Exception("Too much bug errors, aborting: %s" % e)
                time.sleep(5)
                try:
                    self.M.logout()
                except:
                    pass

                if self.get_state() in ('noninit', 'nonauth'):
                    self.createIMAPClient()
                elif self.get_state() == 'auth':
                    self.createIMAPClient()
                    self.loginIMAPCLient()
                elif self.get_state() == 'selected':
                    self.createIMAPClient()
                    self.loginIMAPCLient()
                    if self.folder_selected:
                        self.select_folderIMAPClient()
                else:
                    raise Exception("State not expectedd %s" % sself.get_state())

    return func_wrapper


class patchedIMAPClient:
    def __init__(self, *args, **kwargs):
        self.init_args = args
        self.init_kwargs = kwargs
        self.M = None
        self.createIMAPClient()
        self.folder_selected = False
        self.state = 'noninit'

    def get_state(self):
        return self.state


    @sslpatch
    def createIMAPClient(self):
        self.M = imapclient.IMAPClient(*self.init_args, **self.init_kwargs)

        self.state = 'nonauth'

        return self.M

    @sslpatch
    def loginIMAPCLient(self):
        l = self.M.login(*self.login_args, **self.login_kwargs)

        self.state = 'auth'

        return l

    def login(self, *args, **kwargs):
        self.login_args = args
        self.login_kwargs = kwargs
        return self.loginIMAPCLient()

    @sslpatch
    def list_folders(self, *args, **kwargs):
        return self.M.list_folders(*args, **kwargs)

    @sslpatch
    def list_sub_folders(self, *args, **kwargs):
        return self.M.list_sub_folders(*args, **kwargs)

    @sslpatch
    def select_folderIMAPClient(self):
        fs = self.M.select_folder(*self.select_folder_args, **self.select_folder_kwargs)

        self.folder_selected = True
        self.state = 'selected'

        return fs

    def select_folder(self, *args, **kwargs):
        self.select_folder_args = args
        self.select_folder_kwargs = kwargs
        return self.select_folderIMAPClient()

    @sslpatch
    def search(self, *args, **kwargs):
        return self.M.search(*args, **kwargs)

    @sslpatch
    def fetch(self, *args, **kwargs):
        return self.M.fetch(*args, **kwargs)

    @sslpatch
    def close_folder(self, *args, **kwargs):
        f = self.M.close_folder(*args, **kwargs)

        self.state = 'auth'

        return f

    @sslpatch
    def logout(self):
        l = self.M.logout()
        self.state = 'noninit'
        return l

    @sslpatch
    def shutdown(self):
        s = self.M.shutdown()
        self.state = 'noninit'
        return s

    @sslpatch
    def append(self, *args, **kwargs):
        return self.M.append(*args, **kwargs)


##################################
def backup(from_host, from_account, from_password, to_filename, from_port=None, from_ssl=True, check_from_hostname=True):
    changes = 0
    log.debug('=== Backing up %s account on %s to file %s...' % (from_account, from_host, to_filename))
    if from_port is None:
        if from_ssl:
            imap_port = 993
        else:
            imap_port = 143

    dest = store_db(to_filename)

    log.debug("* Logging in to %s with acccount %s..." % (from_host, from_account))
    ssl_context = None
    if not check_from_hostname:
        ssl_context = imapclient.tls.create_default_context()
        ssl_context.check_hostname = False

    M = patchedIMAPClient(from_host, port=from_port, use_uid=True, ssl=from_ssl, ssl_context=ssl_context)
    M.login(from_account, from_password)

    subscribed_folders = [x[2] for x in M.list_sub_folders()]
    folders = []
    for v in M.list_folders():
        subscribed = v[2] in subscribed_folders
        folders.append((*v,subscribed))


    fmb = dict([(x[2], x[3]) for x in folders])
    dest.c.execute("""select m.id, m.name, m.subscribed
                     from mailbox m""")
    for id, mailbox, subscribed in dest.c.fetchall():
        if mailbox not in fmb:
            log.debug('+ Deleting mailbox %s and all messages within...' % mailbox)
            dest.c.execute("""delete from message
                             where mailbox_id=?""", (id, ))
            changes += 1
            dest.c.execute("""delete from mailbox
                             where id=?""", (id,))
            changes += 1
        else:
            subscribed9 = 1 if fmb[mailbox] else 0
            if subscribed!=subscribed9:
                log.debug('+ Updating mailbox %s...' % mailbox)
                dest.c.execute("""update mailbox
                                 set subscribed=?
                                 where id=?""", (subscribed9, id))
                changes += 1

    for i, (flags, delimiter, mailbox, subscribed) in enumerate(folders, 1):
        log.debug("* Processing %smailbox %s %i/%i..." % ('subscribed ' if subscribed else 'unsubscribed ', mailbox, i, len(folders)))

        log.debug('+ Creating mailbox...')
        exists = dest.create_mailbox(mailbox, subscribed=subscribed)
        if exists:
            log.debug("- Already exists. The existing one will be used.")
        else:
            changes += 1

        dest.c.execute("select m.id from mailbox m where m.name=?", (mailbox, ))
        mailbox_id = dest.c.fetchone()[0]

        log.debug("+ Reading message list...")
        M.select_folder(mailbox, readonly=True)
        uid_list = M.search(['NOT', 'DELETED']) # cerquem ls uids interns de tots els missatge del folder antertior

        num_msgs = len(uid_list)
        log.debug("- %i messages found." % num_msgs)
        
        if num_msgs > 0:
            log.debug("+ Reading message data...")
            down_msgs, dup_msgs, old_msgs, nodate_msgs = 0, 0, 0, 0
            msg_exist = set()

            uid_chunks = split_chunks_by_size(M, uid_list, 20)
            for j, (uid_chunk, chunk_size) in enumerate(uid_chunks, 1):
                down_bytes = 0
                log.debug("- Processing messsage block (%i messages %iKiB) %i/%i..." % (len(uid_chunk), chunk_size/1024, j, len(uid_chunks)))
                chunk_messages = M.fetch(uid_chunk, ['FLAGS', 'INTERNALDATE',
                                                     'BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]',
                                                     'BODY.PEEK[HEADER]',
                                                     'BODY.PEEK[HEADER.FIELDS (SUBJECT)]',
                                                     'RFC822.SIZE' ])
                for uid, message in chunk_messages.items():
                    ep = email.parser.BytesParser()
                    hp = ep.parsebytes(message[b'BODY[HEADER]'], headersonly=True)
                    if hp['Date'] is None:
                        log.debug("- WARNING: Message without header date: Date: %s, Subject: %s. On restore, the message will have the date of restoration." % (message[b'INTERNALDATE'],
                                                                                                                                                                    message[b'BODY[HEADER.FIELDS (SUBJECT)]'].decode().strip()))
                        nodate_msgs +=  1

                    message_id = get_message_id(message)
                    if message_id not in msg_exist:
                        dest.c.execute("""select 1
                                          from message m
                                          where m.mailbox_id=? and
                                                m.message_id=?""", (mailbox_id, message_id))
                        res=dest.c.fetchone()
                        if res is None:
                            [message_body] = M.fetch(uid, ['BODY.PEEK[]']).values()
                            message.update(message_body)

                            message_pickle = pickle.dumps(message, pickle.HIGHEST_PROTOCOL)
                            message_pickle_bz2 = bz2.compress(message_pickle, compresslevel=9)
                            dest.c.execute("""insert into message (message_id, message, mailbox_id)
                                                  values (?,?,?)""", (message_id, message_pickle_bz2, mailbox_id))
                            down_msgs += 1
                            down_bytes += int(message[b'RFC822.SIZE'])
                            changes += 1
                        else:
                            old_msgs +=1
                    else:
                        dup_msgs += 1

                    msg_exist.add(message_id)

                if down_bytes!=0:
                    log.debug("> %i KiB downloaded" % (down_bytes/1024, ))

                dest.conn.commit()
                
            ## delete messages existing in backup and not in imap server
            dest.c.execute("""select m.message_id
                                  from message m
                                  where m.mailbox_id=?""", (mailbox_id, ))
            del_db_msgs = 0
            for (r, ) in dest.c.fetchall():
                if r not in msg_exist:
                    dest.c.execute("""delete from message
                                      where mailbox_id=? and
                                            message_id=?""", (mailbox_id, r))
                    del_db_msgs+=1
                    changes += 1

            dest.conn.commit()

            dest.c.execute("""select count(*)
                                  from message m
                                  where m.mailbox_id=?""", (mailbox_id, ))
            db_msgs = dest.c.fetchone()[0]

            log.debug("= Source messages processed: %i = (new downloaded: %i + existing: %i + duplicated: %i )" % (num_msgs, down_msgs, old_msgs, dup_msgs))
            log.debug("= Source messages without date: %i" % nodate_msgs)
            log.debug("= DB messages: existing: %i, deleted %i" % (db_msgs, del_db_msgs, ))
            
                                        
        M.close_folder()

    M.logout()

    hash_filename = '%s.sha512' % to_filename
    log.debug("Generating sha512 to file %s..." % hash_filename)
    dest.sha512(to_file=hash_filename)

    dest.logout()

    log.debug("======== Total changes: %i" % changes)

    return changes


def restore(from_filename, to_host, to_account, to_password, to_ssl=True):
    print('=== Restoring %s file to %s account on %s...' % (from_filename, to_account, to_host))
    
    src = store_db(from_filename)

    dest = store_imap(to_host, to_account, to_password, ssl=to_ssl)

    src.c.execute("select m.name, m.subscribed, m.id from mailbox m")
    mailboxes = src.c.fetchall()
    for mailbox, subscribed, mailbox_id in mailboxes:
        print("* Processing %smailbox %s..." % ('subscribed ' if subscribed else 'unsubscribed ', mailbox))

        print(" " * 3, '+ Creating mailbox...')
        mailbox_exists = dest.create_mailbox(mailbox, subscribed)
        if mailbox_exists:
            print(" "*6, "- Already exists. The existing one will be used.")

        src.c.execute("select m.message_id from message m where m.mailbox_id=?", (mailbox_id,))
        src_message_ids = src.c.fetchall()
        src_num_msgs = len(src_message_ids)
        print(" " * 3, "+ %i messages found." % src_num_msgs)

        upl_msgs, dup_msgs, old_msgs = 0, 0, 0
        if src_num_msgs > 0:
            dest.M.select_folder(mailbox)
            dest_uids = dest.M.search(['NOT', 'DELETED'])  # find internal uids of all messages of the previous folder
            dest_headers = dest.M.fetch(dest_uids, ['FLAGS', 'INTERNALDATE',
                                                    'BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]',
                                                    'BODY.PEEK[HEADER]',
                                                    'BODY.PEEK[HEADER.FIELDS (SUBJECT)]',
                                                    'RFC822.SIZE'
                                                    ])
            dest_message_ids = [get_message_id(x) for x in dest_headers.values()]

            src_sql = """select m.message_id, message
                         from message m
                         where m.mailbox_id=? and
                               m.message_id not in (%s)""" % ','.join('?'*len(dest_message_ids))

            src_messages = src.c.execute(src_sql, (mailbox_id, *dest_message_ids))
            for message_id, message_pickle_bz2 in src_messages:
                message_pickle = bz2.decompress(message_pickle_bz2)
                message = pickle.loads(message_pickle)
                dest.M.append(mailbox, message[b'BODY[]'], message[b'FLAGS'], message[b'INTERNALDATE'])
                upl_msgs += 1

            dest.M.close_folder()

        print(" "*3, "= Processed messages: %i, uploaded: %i" % (src_num_msgs, upl_msgs))

    dest.logout()
    src.logout()

# TODO: Refactor everything
# TODO: Backup to folder level, more efficient and dealing with smaller files.
# TODO: Save all folder flags.
# TODO: Restore method still in development, it does not work at the moment
# TODO: On restore, set the date on messages withuot "Date" source header.
# TODO: Option to exclude any folder, for instance the folder Trash
         

