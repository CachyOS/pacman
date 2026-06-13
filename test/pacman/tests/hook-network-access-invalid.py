self.description = "Abort on invalid NetworkAccess value in hook"

self.add_script("hook-script", ": > hook-output")
self.add_hook("hook",
        """
        [Trigger]
        Type = Package
        Operation = Install
        Target = foo

        [Action]
        When = PreTransaction
        NetworkAccess = yes
        Exec = bin/hook-script
        """);

sp = pmpkg("foo")
self.addpkg2db("sync", sp)

self.args = "-S foo"

self.addrule("!PACMAN_RETCODE=0")
self.addrule("!PKG_EXIST=foo")
self.addrule("!FILE_EXIST=hook-output")
self.addrule("PACMAN_OUTPUT=failed to run transaction hooks")
