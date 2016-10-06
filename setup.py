from distutils.core import setup


setup(name='imapbackup',
      version='0.1',
      author="NuoBiT Solutions, S.L., Eric Antones",
      author_email='eantones@nuobit.com',
      py_modules=['imapbackup.imapbackup'],
      package_dir={'imapbackup': 'src'},
      #packages=['imapbackup'],
      install_requires=[
          'imapclient',
      ],
      classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Operating System :: POSIX :: Linux',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.5',
        'Topic :: System :: Archiving :: Backup',
      ]
)
