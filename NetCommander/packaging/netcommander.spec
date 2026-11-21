# PyInstaller spec:  pyinstaller packaging/netcommander.spec
# Builds a windowed app on the OS it is run on (Windows .exe / macOS .app / Linux binary).
# NOT verified in the development sandbox - run it on each target OS and smoke-test the result.
from PyInstaller.utils.hooks import collect_all, collect_submodules

datas, binaries, hiddenimports = [], [], collect_submodules("netcommander")
for pkg in ("customtkinter", "ntc_templates", "netmiko", "pyotp"):
    d, b, h = collect_all(pkg)
    datas += d; binaries += b; hiddenimports += h
hiddenimports += ["matplotlib.backends.backend_tkagg"]

a = Analysis(["../netcommander.py"], pathex=[".."], datas=datas, binaries=binaries,
             hiddenimports=hiddenimports, excludes=["pytest"])
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="NetCommander", console=False)
coll = COLLECT(exe, a.binaries, a.datas, name="NetCommander")
import sys
if sys.platform == "darwin":
    app = BUNDLE(coll, name="NetCommander.app", bundle_identifier="org.netcommander.app")
