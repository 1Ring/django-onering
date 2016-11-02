import os
from setuptools import setup
 
README = open(os.path.join(os.path.dirname(__file__), 'README.rst')).read()
 
# Allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))
 
setup(
    name = 'django-onering',
    version = '0.1',
    packages = ['onering'],
    include_package_data = True,
    license = 'Intel License',
    description = 'OneRing cryptographic identity manager for Django.',
    long_description = README,
    url = 'http://github.com/1ring/1ring/',
    author = 'Bryce Weiner',
    author_email = 'bryce@altsystem.io',
    install_requires =[
        'ecdsa==0.13',
        'secp256k1==0.13.2',
        'python-bitcoinrpc==1.0',
        'pycrypto==2.6.1'
    ],
    classifiers =[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Intel License', # example license
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content'
    ]
)