import cookielib
import functools
import hashlib
import json
import optparse
import os
from Queue import Queue
import subprocess
import sys
import thread
import threading
import traceback
import urllib2

import jwt
from poster.encode import multipart_encode
from poster.streaminghttp import (StreamingHTTPHandler, StreamingHTTPRedirectHandler,
                                  StreamingHTTPSHandler)

# see main()
hashes = {}
queue = None
options = None
exceptions = []


def main():
    global queue, options
    op = optparse.OptionParser(usage='%prog [options] path/to/file/or/directory')
    op.add_option('--server', help='rockit server. default: %default',
                  default='http://localhost:8000')
    op.add_option('--email', help='browserID email')
    op.add_option('--keypath', help='path to your upload key. '
                                    'default: %default',
                  default=os.path.join(os.path.dirname(__file__),
                                       'upload_key.txt'))
    op.add_option('--workers', help='number of worker threads. '
                                    'default: %default',
                  action='store', default=4, type=int)
    op.add_option('--verbose', help='moar output',
                  action='store_true')
    (options, args) = op.parse_args()
    if len(args) != 1:
        op.error('incorrect usage')
    path = args[0]

    handlers = [StreamingHTTPHandler, StreamingHTTPRedirectHandler, StreamingHTTPSHandler]
    cj = cookielib.CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj), *handlers)
    urllib2.install_opener(opener)

    if not options.email:
        op.error('--email is required')
    info('server: %s' % options.server)

    queue = Queue()
    debug('starting %s workers' % options.workers)
    for i in range(options.workers):
         th = threading.Thread(target=worker)
         th.daemon = True
         th.start()

    if os.path.isfile(path):
        upload_file(path)
    else:
        upload_dir(path)

    queue.join()  # block until all tasks are done
    check_all_hashes(force=True)  # push any stragglers
    queue.join()
    success = True
    for etype, val, tb in exceptions:
        success = False
        info('')
        traceback.print_exception(etype, val, tb)
        info('')
    info('Number of exceptions: %s' % len(exceptions))
    info('Done!')
    sys.exit(0 if success else 1)


class QueuableObject:

    def __init__(self, fn):
        self.fn = fn

    def __call__(self, *args, **kw):
        return self.fn(*args, **kw)

    def __unicode__(self):
        return u'<%s %s>' % (self.__class__.__name__, self.fn)

    def __str__(self):
        return str(self.__unicode__())

    def delay(self, *args, **kw):
        queue.put(lambda: self.fn(*args, **kw))


def qtask(fn):
    return functools.wraps(fn)(QueuableObject(fn))


@qtask
def check_hash(filename):
    with open(filename) as fp:
        hash = hashlib.sha1()
        while True:
            chunk = fp.read(1024 * 100)
            if not chunk:
                break
            hash.update(chunk)
        push_hash(filename, hash.hexdigest())


@qtask
def upload(filename, sha1):
    debug('uploading %s' % filename)
    with open(filename) as fp:
        sig_req = jwt.encode({'iss': options.email, 'aud': options.server},
                             read_key(options.keypath))
        if isinstance(filename, unicode):
            filename = filename.encode('utf8')
        params = {filename: fp, 'r': sig_req, 'sha1': sha1}
        data, headers = multipart_encode(params)
        req = urllib2.Request('%s/upload' % options.server, data, headers)
        result = read_request(req)
        debug('uploaded %s' % fp.name)


@qtask
def maybe_upload(all_hashes):
    sig_req = jwt.encode({'iss': options.email, 'aud': options.server,
                          'request': {'sha1s': all_hashes.keys()}},
                         read_key(options.keypath))
    req = urllib2.Request('%s/checkfiles?r=%s' % (options.server, sig_req))
    result = read_request(req)
    data = json.loads(result)
    debug('checking if %s hashes exist' % len(all_hashes))
    for sha1, exists in data['sha1s'].items():
        filename = all_hashes[sha1]
        if not exists:
            upload.delay(filename, sha1)
        else:
            debug('not uploading; already exists: %s' % filename)


def worker():
    while True:
        task = queue.get()
        try:
            debug('running task %s' % task)
            task()
        except Exception, exc:
            info('EXCEPTION: %s: %s' % (type(exc).__name__, exc))
            exceptions.append(sys.exc_info())
        finally:
            debug('finishing task')
            queue.task_done()


def debug(msg):
    if options.verbose:
        print '[%s] ** %s' % (thread.get_ident(), msg)


def info(msg):
    print '[%s] %s' % (thread.get_ident(), msg)


def read_key(path):
    with open(path, 'rb') as fp:
        return str(fp.read().strip())


def read_request(req):
    debug('reading request: %s' % req)
    try:
        return urllib2.urlopen(req).read()
    except Exception, exc:
        info(exc.headers)
        with open('./error-msg.html', 'w') as fp:
            fp.write(exc.read())
        info('Error in %s' % fp.name)
        raise


def push_hash(filename, sha1):
    hashes[sha1] = filename
    with threading.Lock():
        check_all_hashes()


def check_all_hashes(force=False):
    if len(hashes) > 10 or force:
        maybe_upload.delay(hashes.copy())
        hashes.clear()
    else:
        debug('check deferred; length: %s' % len(hashes))


def upload_file(path):
    debug('syncing %s' % path)
    if not path.lower().endswith('mp3'):
        raise ValueError('Can only sync mp3 files')
    check_hash.delay(path)


def upload_dir(path):
    info('syncing directory %s' % path)
    for root, dirs, files in os.walk(path):
        for fn in files:
            check_hash.delay(os.path.join(root, fn))


if __name__ == '__main__':
    main()
