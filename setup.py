from setuptools import setup

setup(name='pythales',
      version='0.74',
      
      description='python thales hsm simulator',
      long_description=open('README.md').read(),
      
      classifiers=[
        'License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)',
        'Operating System :: OS Independent',
        
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        
        'Topic :: Communications',
        'Intended Audience :: Developers',
      ],
      
      keywords='thales hsm',
      
      url='https://github.com/timgabets/pythales',
      author='Tim Gabets',
      author_email='tim@gabets.ru',
      
      license='LGPLv2',
      packages=['pythales'],
      install_requires=['pycrypto', 'tracetools', 'pynblock'],
      zip_safe=True)
