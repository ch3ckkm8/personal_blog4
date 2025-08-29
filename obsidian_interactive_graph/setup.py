import os

from setuptools import setup, find_packages

def read_file(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='mkdocs-obsidian-interactive-graph-plugin',
    version='0.1.0',  # <-- hardcode version instead of use_scm_version
    description='A MkDocs plugin that generates a obsidian like interactive graph',
    long_description=read_file('README.md'),
    long_description_content_type='text/markdown',
    keywords='mkdocs',
    url='https://github.com/daxcore/mkdocs-obsidian-interactive-graph-plugin',
    author='daxcore',
    author_email='300ccda6-8d43-4f23-808e-961e653ff7d6@anonaddy.com',
    license='MIT',
    python_requires='>=3.6',
    install_requires=['mkdocs-material'],
    packages=find_packages(),
    entry_points={
        'mkdocs.plugins': [
            'obsidian-interactive-graph = obsidian_interactive_graph.plugin:ObsidianInteractiveGraphPlugin'
        ]
    }
)

