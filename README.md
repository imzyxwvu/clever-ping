clever-ping
===========

A super-fast lightweight multi-target monitoring daemon with JSON HTTP API. Multiple
hosts can be watched and real-time state can be queried with HTTP.

How to Build
------------

You could build clever-ping easily with cmake:

```
# [Optional] Install prerequists
sudo apt install libuv1-dev libhttp-parser-dev libjson-c-dev
# Build with CMake3
mkdir build && cd build && cmake .. && make -j
# Run clever-ping requires superuser privileges
./clever-ping
```

Usage
-----

Ping targets can be registered via a file specified with command line option `-i` or
POST requests to `http://localhost:8001/tgt`. Both ways obey the same JSON syntax.
With POST requests, you can add targets on the fly.

```
/* Save as tgt.json and run with `./clever-ping -i tgt.json` */
{
    "8.8.8.8": { "interval": 5000, "timeout": 500 },
    "2001:4860:4860::8888": { "interval": 6000 }
}
```

You can query realtime report over all targets like this:

```
# curl localhost:8001/tgt
{"8.8.8.8":{"state":"ok","latency":56},"2001:4860:4860::8888":{"state":"ok","latency":298}}
```

You can also change API listen address and port with option `-b` and option `-p`.

Copyright
---------

    Copyright © 2021 zyxwvu Shi

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

