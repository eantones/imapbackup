from distutils.core import setup


setup(name='imapbackup',
      version='v0.1.0',
      author="NuoBiT Solutions, S.L., Eric Antones",
      author_email='eantones@nuobit.com',
      py_modules=['imapbackup.imapbackup'],
      package_dir={'imapbackup': 'src'},
      install_requires=[
          'tzlocal',
          'imapclient',
      ],
      url='https://github.com/nuobit/imapbackup',
      #download_url = 'https://github.com/eantones/imapbackup/archive/0.1.tar.gz',
      keywords = ['imap', 'backup', 'incremental'],
      license='AGPLv3+',
      platform='Linux',
      description='Incremental imap backup',
      long_description='Backs up an imap account entirely',
      classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Operating System :: POSIX :: Linux',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Topic :: System :: Archiving :: Backup',
      ]
)
