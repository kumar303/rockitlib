rockitlib
=========

A thin library to upload your mp3 files to a
[rockit server](https://github.com/kumar303/rockit) for
[Herbie](https://github.com/ednapiranha/herbie), an html5 music player.

It requires Python 2.6 or greater.
Run this from a virtualenv to install it:

    pip install -r requirements.txt

Ask the rockit server admin to grant you an upload key then put that in
``./upload_key.txt``.
Start syncing music like this:

    python musicsync.py path/to/mp3/or/directory --email <browserID email>

See ``--help`` for usage.
