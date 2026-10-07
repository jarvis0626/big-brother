"""Freeze runtime only. Training/PyTorch and public telemetry are not bundled."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
os.environ['PYINSTALLER_CONFIG_DIR'] = str(ROOT / '.cache' / 'pyinstaller')
temp = ROOT / '.cache' / 'temp'
temp.mkdir(parents=True, exist_ok=True)
os.environ['TEMP'] = os.environ['TMP'] = str(temp)
subprocess.run([sys.executable, str(ROOT / 'scripts' / 'icons.py')], check=True)
subprocess.run([
    sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir',
    '--name', 'big-brother-service', '--console', '--icon', str(ROOT / 'assets' / 'icon.ico'),
    '--distpath', str(ROOT / 'dist' / 'backend-stage'), '--workpath', str(ROOT / 'build' / 'backend'),
    '--specpath', str(ROOT / 'build'), '--paths', str(ROOT),
    '--exclude-module', 'torch', '--exclude-module', 'sklearn', '--exclude-module', 'pytest',
    str(ROOT / 'scripts' / 'service_entry.py')
], cwd=ROOT, check=True)
import shutil
destination = ROOT / 'dist' / 'backend'
if destination.exists():
    resolved = destination.resolve()
    if not resolved.is_relative_to(ROOT / 'dist'):
        raise RuntimeError('Unsafe build output path')
    shutil.rmtree(resolved)
shutil.copytree(ROOT / 'dist' / 'backend-stage' / 'big-brother-service', destination)
from importlib.metadata import distribution
licences = destination / 'licences'
licences.mkdir(exist_ok=True)
shutil.copyfile(Path(sys.base_prefix) / 'LICENSE.txt', licences / 'Python-LICENSE.txt')
for package in ('psutil', 'pyinstaller'):
    dist = distribution(package)
    for item in dist.files or []:
        if item.name.upper() in ('LICENSE', 'LICENSE.TXT', 'COPYING.TXT', 'COPYING'):
            licence_path = Path(dist.locate_file(item))
            if licence_path.is_file(): shutil.copyfile(licence_path, licences / f'{package}-{item.name}')
print(f'Frozen runtime: {destination}')
