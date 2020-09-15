import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="hydrocarbon",
    version="0.0.2",
    author="David Cannings",
    author_email="david@edeca.net",
    description="Generate a Carbon Black alliance feed in JSON format from a git repository",
    license="Apache Software License",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/edeca/hydrocarbon",
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts': ['hydrocarbon=hydrocarbon.app:main'],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
    ],
    install_requires=[
        'Pillow',
        'PyYAML',
        'GitPython',
    ],
)
