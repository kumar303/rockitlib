import cookielib
import hashlib
import optparse
import os
import subprocess
import urllib2

import jwt
from poster.encode import multipart_encode
from poster.streaminghttp import (StreamingHTTPHandler, StreamingHTTPRedirectHandler,
                                  StreamingHTTPSHandler)


def main():
    op = optparse.OptionParser(usage='%prog [options]')
    op.add_option('--file', help='path to a single file to sync')
    op.add_option('--server', help='rockit server. default: %default',
                  default='http://localhost:8000')
    op.add_option('--email', help='browserID email')
    op.add_option('--keypath', help='path to your upload key. '
                                    'default: %default',
                  default=os.path.join(os.path.dirname(__file__),
                                       'upload_key.txt'))
    (options, args) = op.parse_args()

    handlers = [StreamingHTTPHandler, StreamingHTTPRedirectHandler, StreamingHTTPSHandler]
    cj = cookielib.CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj), *handlers)
    urllib2.install_opener(opener)

    if not options.email:
        op.error('--email is required')
    print 'server: %s' % options.server
    if options.file:
        print 'syncing %s' % options.file
        if not options.file.lower().endswith('mp3'):
            op.error('Can only sync mp3 files')
        with open(options.file) as fp:
            hash = hashlib.sha1()
            while True:
                chunk = fp.read(1024 * 100)
                if not chunk:
                    break
                hash.update(chunk)
            sha1 = hash.hexdigest()
        with open(options.file) as fp:
            sig_req = jwt.encode({'iss': options.email, 'aud': options.server},
                                 read_key(options.keypath))
            params = {options.file: fp, 'sig_request': sig_req, 'sha1': sha1}
            data, headers = multipart_encode(params)
            req = urllib2.Request('%s/upload' % options.server, data, headers)
            try:
                result = urllib2.urlopen(req)
            except Exception, exc:
                print exc.headers
                with open('./error-msg.html', 'w') as fp:
                    fp.write(exc.read())
                print 'Error in %s' % fp.name
                raise
            print 'success'


def read_key(path):
    with open(path, 'rb') as fp:
        return str(fp.read().strip())


if __name__ == '__main__':
    main()
