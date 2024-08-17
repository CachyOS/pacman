self.description = 'download remote packages with -U with a URL filename'
self.require_capability("gpg")
self.require_capability("curl")

url = self.add_simple_http_server({
    # simple
    '/simple.pkg': 'simple',
    '/simple.pkg.sig': {
        'headers': { 'Content-Disposition': 'attachment; filename="simple.sig-alt' },
        'body': 'simple.sig',
    },

    # content-disposition filename is now ignored
    '/cd.pkg': {
        'headers': { 'Content-Disposition': 'attachment; filename="cd-alt.pkg"' },
        'body': 'cd'
    },
    '/cd.pkg.sig': 'cd.sig',

    # redirect
    '/redir.pkg': { 'code': 303, 'headers': { 'Location': '/redir-dest.pkg' } },
    '/redir-dest.pkg': 'redir-dest',
    '/redir-dest.pkg.sig': 'redir-dest.sig',

    # redirect cdn
    '/redir-cdn.pkg': { 'code': 303, 'headers': { 'Location': '/cdn-1' } },
    '/redir-cdn.pkg.sig': { 'code': 303, 'headers': { 'Location': '/cdn-2' } },
    '/cdn-1': 'redir-dest',
    '/cdn-2': 'redir-dest.sig',

    # content-disposition and redirect
    '/cd-redir.pkg': { 'code': 303, 'headers': { 'Location': '/cd-redir-dest.pkg' } },
    '/cd-redir-dest.pkg': {
        'headers': { 'Content-Disposition': 'attachment; filename="cd-redir-dest-alt.pkg"' },
        'body': 'cd-redir-dest'
    },
    '/cd-redir-dest.pkg.sig': 'cd-redir-dest.sig',

    # content-disposition and redirect to cdn
    '/cd-redir-cdn.pkg': { 'code': 303, 'headers': { 'Location': '/cdn-3' } },
    '/cd-redir-cdn.pkg.sig': { 'code': 303, 'headers': { 'Location': '/cdn-4' } },
    '/cdn-3': {
        'headers': { 'Content-Disposition': 'attachment; filename="cdn-alt.pkg"' },
        'body': 'cdn-alt'
    },
    '/cdn-4': {
        'headers': { 'Content-Disposition': 'attachment; filename="cdn-alt.pkg.sig"' },
        'body': 'cdn-alt.sig'
    },

    # TODO: absolutely terrible hack to prevent pacman from attempting to
    # validate packages, which causes failure under --valgrind thanks to
    # a memory leak in gpgme that is too general for inclusion in valgrind.supp
    '/404': { 'code': 404 },

    '': 'fallback',
})

self.args = '-Uw {url}/simple.pkg {url}/cd.pkg {url}/redir.pkg {url}/redir-cdn.pkg {url}/cd-redir.pkg {url}/cd-redir-cdn.pkg {url}/404'.format(url=url)

# packages/sigs are not valid, error is expected
self.addrule('!PACMAN_RETCODE=0')

self.addrule('CACHE_FCONTENTS=simple.pkg|simple')
self.addrule('CACHE_FCONTENTS=simple.pkg.sig|simple.sig')

self.addrule('!CACHE_FEXISTS=cd-alt.pkg')
self.addrule('!CACHE_FEXISTS=cd-alt.pkg.sig')
self.addrule('CACHE_FCONTENTS=cd.pkg|cd')
self.addrule('CACHE_FCONTENTS=cd.pkg.sig|cd.sig')

self.addrule('!CACHE_FEXISTS=redir-dest.pkg')
self.addrule('CACHE_FCONTENTS=redir.pkg|redir-dest')
self.addrule('CACHE_FCONTENTS=redir.pkg.sig|redir-dest.sig')

self.addrule('CACHE_FCONTENTS=redir-cdn.pkg|redir-dest')
self.addrule('CACHE_FCONTENTS=redir-cdn.pkg.sig|redir-dest.sig')

self.addrule('!CACHE_FEXISTS=cd-redir-dest-alt.pkg')
self.addrule('!CACHE_FEXISTS=cd-redir-dest-alt.pkg')
self.addrule('CACHE_FCONTENTS=cd-redir.pkg|cd-redir-dest')
self.addrule('CACHE_FCONTENTS=cd-redir.pkg.sig|cd-redir-dest.sig')

self.addrule('!CACHE_FEXISTS=cdn-3')
self.addrule('!CACHE_FEXISTS=cdn-4')
self.addrule('!CACHE_FEXISTS=cdn-alt.pkg')
self.addrule('!CACHE_FEXISTS=cdn-alt.pkg.sig')
self.addrule('CACHE_FCONTENTS=cd-redir-cdn.pkg|cdn-alt')
self.addrule('CACHE_FCONTENTS=cd-redir-cdn.pkg.sig|cdn-alt.sig')
