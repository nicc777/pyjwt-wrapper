from setuptools import setup, find_packages
import pathlib


here = pathlib.Path(__file__).parent.resolve()
long_description = (here / 'README.md').read_text(encoding='utf-8')
setup(
    name='pyjwt-wrapper',
    version='0.6.0',
    description='An easy to use wrapper around PyJWT for authentication and authorization.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/nicc777/pyjwt-wrapper',
    author='Nico Coetzee',
    author_email='nicc777@gmail.com',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3 :: Only',
    ],
    keywords='jwt, pyjwt, library',
    package_dir={'': 'src'},
    packages=find_packages(where='src'),
    python_requires='>=3.7, <4',
    install_requires=['pyjwt'],
    extras_require={ 
        'dev': ['check-manifest'],
        'test': ['coverage'],
    },
    project_urls={
        'Bug Reports': 'https://github.com/nicc777/pyjwt-wrapper/issues',
        'Source': 'https://github.com/nicc777/pyjwt-wrapper',
    },
)
