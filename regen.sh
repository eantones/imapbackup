PYPATH=~/opt/python/venvs/py35

$PYPATH/bin/python setup.py sdist
$PYPATH/bin/pip uninstall -y imapbackup
$PYPATH/bin/pip install dist/*0.1*
