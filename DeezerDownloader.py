#!/usr/bin/env python3

import requests
import re
import json
import os
import argparse
from binascii import hexlify
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class DeezerDownloader():
    def __init__(self, email, password):
        self.session = requests.session()
        self.header = {
                'Pragma': 'no-cache' ,
                'Origin': 'https://www.deezer.com' ,
                'Accept-Encoding': 'gzip, deflate, br' ,
                'Accept-Language': 'en-US,en;q=0.9' ,
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36' ,
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' ,
                'Accept': '*/*' ,
                'Cache-Control': 'no-cache' ,
                'X-Requested-With': 'XMLHttpRequest' ,
                'Connection': 'keep-alive' ,
                'Referer': 'https://www.deezer.com/login' ,
                'DNT': '1' ,
            }
        self.session.headers.update(self.header)
        self.email = email
        self.password = password
        self.url = 'https://www.deezer.com'
        self.path = 'Download/'
        self._login()
    
    def _login(self):
        self.session.get(self.url + "/login")
        resp = self.session.post(self.url + "/ajax/gw-light.php?method=deezer.getUserData&input=3&api_version=1.0&api_token=&cid=")
        csrf_token = resp.json()['results']['checkFormLogin']
        payload = {
            'type': 'login',
            'mail': self.email,
            'password': self.password,
            'checkFormLogin': csrf_token
        }
        self.session.post(self.url + "/ajax/action.php", data=payload)
        return print("Login succesful")
    
    def _get_json(self, s, first, last):
        try:
            start = s.index(first) + len(first)
            end = s.index(last, start)
            return s[start:end]
        except ValueError:
            return ""
    
    def _decrypt_song(self, track, sngid):
        intervalchunk = 3
        chunksize = 2048
        position = 0
        readtotal = 0
        i = 0
        read = 0
        first = True
        backend = default_backend()
        blowfishkey = self._get_blowfish_key(sngid).encode("utf-8")
        ebuffer = bytearray(b'\0' * (len(track) + (chunksize - (len(track) - (int(len(track) / chunksize) * chunksize)))))

        while position <= len(track):
            chunk = b'\0' * chunksize
            chunk = track[position:position + chunksize]
            if i % intervalchunk == 0:
                cipher = Cipher(algorithms.Blowfish(blowfishkey), modes.CBC(b'\x00\x01\x02\x03\x04\x05\x06\x07'), backend=backend)
                decryptor = cipher.decryptor()
                chunk = decryptor.update(chunk + ((b'\x00' * (8 - len(chunk) % 8)) if len(chunk) % 8 != 0 else b''))
            if first:
                first = False
            ebuffer[position:position + len(chunk)] = chunk
            position += chunksize
            i += 1
            readtotal += position
        return ebuffer
    
    def _get_blowfish_key(self, id):
        if int(id) < 1:
            id *= -1
        hash = hashlib.md5(str(id).encode("latin1"))
        hpart = hash.hexdigest()[0:16]
        lpart = hash.hexdigest()[16:32]
        parts = ['g4el58wc0zvf9na1', hpart, lpart]
        return self._xor_hex(parts)

    def _xor_hex(self, parts):
        data = ""
        i = 0
        while i < 16:
            character = ord(parts[0][i])
            j = 1
            while j < len(parts):
                character ^= ord(parts[j][i])
                j += 1
            data += chr(character)
            i += 1
        return data
        # e=ljcm"f>){bo:b5

    def _getSongData(self, id):
        r = self.session.get(self.url + "/us/track/" + id)
        if "MD5_ORIGIN" in r.text:
            jsonData = json.loads(self._get_json(r.text, '<script>window.__DZR_APP_STATE__ = ', '</script>'))
            return jsonData

    def _downloadSong(self, id):
        jsonData = self._getSongData(id)
        if not jsonData:
            print("Song unavailable")
            return
        md5_origin = jsonData["DATA"]["MD5_ORIGIN"]
        mformat = 3
        if int(jsonData['DATA']['FILESIZE_MP3_320']) <= 0:
            if int(jsonData['DATA']['FILESIZE_MP3_256']) > 0:
                mformat = 5
            else:
                mformat = 1
        media_version = jsonData['DATA']['MEDIA_VERSION']
        url_part = str(md5_origin) + chr(164) + str(mformat) + chr(164) + str(id) + chr(164) + str(media_version)
        val_md5 = hashlib.md5(url_part.encode("latin1")).hexdigest()
        url_part2 = val_md5 + chr(164) + url_part + chr(164)
        url = url_part2.encode('latin1')
        backend = default_backend()
        cipher = Cipher(algorithms.AES(b"jo6aey6haid2Teih"), modes.ECB(), backend=backend)
        encryptor = cipher.encryptor()
        val_aes = encryptor.update(url + ((b'\x00' * (16 - len(url) % 16)) if len(url) % 16 != 0 else b'')) + encryptor.finalize()
        download_link = "http://e-cdn-proxy-{}.deezer.com/mobile/1/{}".format(md5_origin[0], hexlify(val_aes).decode("ascii"))
        song_bytes = self.session.get(download_link)
        song = self._decrypt_song(song_bytes.content, id)
        artist = jsonData['DATA']['ART_NAME']
        songname = jsonData['DATA']['SNG_TITLE']
        songhandling = '{} - {}.mp3'.format(artist, songname)
        songhandling = re.sub(u"(\u2018|\u2019)", "'", songhandling)
        songhandling = songhandling.replace('/', '')
        songhandling = songhandling.replace('*', '')
        songhandling = songhandling.replace('?', '')
        songhandling = songhandling.replace('"', '')
        songhandling = songhandling.replace('<', '')
        songhandling = songhandling.replace('>', '')
        songhandling = songhandling.replace('|', '')
        path = self.path + songhandling
        try:
            os.mkdir(self.path)
        except FileExistsError:
            pass
        with open(path, 'wb') as of:
            of.write(song)
        print("Downloaded: " + songhandling)

    def _downloadPlaylist(self, id):
        r = self.session.get(self.url + "/us/playlist/" + str(id))
        jsonData = json.loads(self._get_json(r.text, '<script>window.__DZR_APP_STATE__ = ', '</script>'))
        print("Playlist WIP! Max 40 Songs!")
        '''
        jsonData['DATA']['NB_SONG'] #number of songs in playlist
        payload = {
            'header': True,
            'nb': jsonData['DATA']['NB_SONG'],
            'playlist_id': id,
        }
        r = self.session.post(self.url + '/ajax/gw-light.php', json=payload)
        '''

        for i in jsonData['SONGS']['data']:
            self._downloadSong(i['SNG_ID'])
        

    def download(self, link):
        if "track" in link:
            split = link.split("/track/")
            self._downloadSong(split[-1])
        if "playlist" in link:
            split = link.split("/playlist/")
            self._downloadPlaylist(split[-1])
    
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='DeezerDownloader')
    parser.add_argument('--email')
    parser.add_argument('--password')
    parser.add_argument('--link')
    parser.add_argument('--path')
    args = parser.parse_args()
    if not args.email:
        print("No email argument provided")
        exit()
    if not args.password:
        print("No password argument provided")
        exit()
    if not args.link:
        print("No link provided")
        exit()
    dee = DeezerDownloader(args.email, args.password)
    if args.path:
        dee.path = args.path + '/'
    dee.download(args.link)
