import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="SOL-Client-Connector-Package",
    version="0.0.0",
    author="Andreas Sas",
    author_email="",
    description="A Connector System to correctly Connect to the SOL API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/DirectiveAthena/S.O.L-Client-Package",
    project_urls={
        "Bug Tracker": "https://github.com/DirectiveAthena/S.O.L-Client-Package/issues",
    },
    license="GPLv3",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.6",
)