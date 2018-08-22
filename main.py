#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import os
import socket
import ssl
import httplib, urlparse
import re

def recupheader(domain, req='/'):
    agent = {'User-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64 x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36'}
    try:
        connexion = httplib.HTTPSConnection(domain, context=ssl._create_unverified_context())
        connexion.request("HEAD", req, headers = agent)
    except socket.error:
        connexion = httplib.HTTPConnection(domain, 80)
        connexion.request("HEAD", req, header = agent)
    r = connexion.getresponse()
    connexion.close()
    return r

def checkheader(r, note=0):
    dicheader = { "x-xss-protection": "no", "content-security-policy":"no", "strict-transport-security":"no", "referrer-policy":"no", "x-content-type-options":"no", "x-frame-options":"no", "public-key-pins":"no" }
    for result in r.getheaders():
        if result[0] in 'x-xss-protection':
            dicheader['x-xss-protection'] = 'ok'
            note = note + 1
        elif result[0] in 'content-security-policy':
            dicheader['content-security-policy'] = 'ok'
            note = note + 1
        elif result[0] in 'strict-transport-security':
            if 'max-age' in result[1]:
                dicheader['strict-transport-security'] = 'ok'
                note = note + 1
        elif result[0] in 'referrer-policy':
            if result[1] in 'no-referrer' or 'same-origin' or 'strict-origin' or 'strict-origin-when-cross-origin':
                dicheader['referrer-policy'] = 'ok'
                note = note + 1
        elif result[0] in 'x-content-type-options':
            if result[1] in 'nosniff':
                dicheader['x-content-type-options'] = 'ok'
                note = note + 1
        elif result[0] in 'x-frame-options':
            if result[1] in 'DENY' or 'SAMEORIGIN' or 'ALLOW-FROM':
                dicheader['x-frame-options'] = 'ok'
                note = note + 1
        elif result[0] in 'public-key-pins':
            dicheader['public-key-pins'] = 'ok'
            note = note + 1

    return dicheader, note

def getresult(dicresult,note):
    for key, value in dicresult.items():
         if value in 'no':
            print key, ':', coloriage(value, 'red', True)
         else:
            print key, ':', coloriage(value, 'green', False)
    print "\nNote : ",notecheck(note),"/7"

def coloriage(s, color, bold=False):
    colors = {'red': 31, 'green': 32, 'yellow': 33,
             'blue': 34}
    if os.getenv('ANSI_COLORS_DISABLED') is None and color in colors:
        if bold:
            return '\033[1m\033[%dm%s\033[0m' % (colors[color], s)
        else:
            return '\033[%dm%s\033[0m' % (colors[color], s)
    else:
        return s

def notecheck(note):
    if note <= 7 and note > 3:
        return coloriage(note, 'green', False)
    elif note <= 3 and note > 1:
        return coloriage(note, 'yellow', False)
    elif note == 0:
        return coloriage(note, 'red', False)
    else:
        return note


if __name__ == '__main__':
    if len (sys.argv) != 2 :
        respuser = raw_input("Entrez un url sans le https : ")
    else:
        respuser = sys.argv[1]
    parseurl = urlparse.urlparse('https://' + respuser)
    url = parseurl[1]
    path = parseurl[2]
    result = recupheader(url, path)
    dicresult, note = checkheader(result)
    print '-----------------------------------------------'
    print '                  CheckSecurity                '
    print '-----------------------------------------------'
    getresult(dicresult,note)
    print '-----------------------------------------------\n '
