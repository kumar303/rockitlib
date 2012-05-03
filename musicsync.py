import cookielib
import optparse
import os
import subprocess
import urllib2

from poster.encode import multipart_encode
from poster.streaminghttp import (StreamingHTTPHandler, StreamingHTTPRedirectHandler,
                                  StreamingHTTPSHandler)


def main():
    op = optparse.OptionParser(usage='%prog [options]')
    op.add_option('--file', help='path to a single file to sync')
    op.add_option('--upload', help='url to upload file. default: %default',
                  default='http://localhost:8000/en-US/upload')
    op.add_option('--email', help='browserID email')
    (options, args) = op.parse_args()

    handlers = [StreamingHTTPHandler, StreamingHTTPRedirectHandler, StreamingHTTPSHandler]
    cj = cookielib.CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj), *handlers)
    urllib2.install_opener(opener)

    if not options.email:
        op.error('--email is required')
    print 'upload URL: %s' % options.upload
    if options.file:
        print 'syncing %s' % options.file
        if not options.file.lower().endswith('mp3'):
            op.error('Can only sync mp3 files')
        with open(options.file) as fp:
            params = {options.file: fp, 'email': options.email}
            data, headers = multipart_encode(params)
            req = urllib2.Request(options.upload, data, headers)
            try:
                result = urllib2.urlopen(req)
            except Exception, exc:
                print exc.headers
                with open('./error-msg.html', 'w') as fp:
                    fp.write(exc.read())
                print 'Error in %s' % fp.name
                #import pdb; pdb.set_trace()
                raise
            print 'success'


if __name__ == '__main__':
    main()
