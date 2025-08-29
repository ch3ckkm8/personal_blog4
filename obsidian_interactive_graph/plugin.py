import json
import os
import re

from mkdocs.config.defaults import MkDocsConfig
from mkdocs.plugins import BasePlugin, get_plugin_logger
from mkdocs.structure.pages import Page as MkDocsPage
from mkdocs.structure.nav import Navigation as MkDocsNav
from mkdocs.structure.files import Files as MkDocsFiles

class ObsidianInteractiveGraphPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.logger = get_plugin_logger(__name__)
        self.nodes = {}   # all nodes: key -> dict with id, title, type, url
        self.data = {"nodes": [], "links": []}
        self.current_id = 0

    @property
    def id(self):
        current = self.current_id
        self.current_id += 1
        return current

    def get_page_path(self, page: MkDocsPage) -> str:
        """Return the relative path of a page, without .md"""
        return page.file.src_uri.replace(".md", "")

    def add_node(self, key: str, title: str, node_type: str = "page", url: str = ""):
        """Add a node if it does not exist"""
        if key not in self.nodes:
            self.nodes[key] = {
                "id": self.id,
                "title": title,
                "type": node_type,
                "url": url,
                "symbolSize": 1
            }

    def collect_pages(self, nav: MkDocsNav, config: MkDocsConfig):
        for page in nav.pages:
            page.read_source(config=config)
            page_path = self.get_page_path(page)
            self.add_node(page_path, page.title, node_type="page", url=page.abs_url)

    def parse_markdown(self, markdown: str, page: MkDocsPage):
        """Parse [[tags]] and create tag nodes + links"""
        TAG_PATTERN = re.compile(r"\[\[(?P<tag>[^\]]+)\]\]")

        page_key = self.get_page_path(page)

        for match in re.finditer(TAG_PATTERN, markdown):
            tag_name = match.group("tag").strip()
            tag_key = f"tag::{tag_name}"  # make sure tag nodes are unique
            self.add_node(tag_key, tag_name, node_type="tag")

            # create link from page -> tag
            self.data["links"].append({
                "source": str(self.nodes[page_key]["id"]),
                "target": str(self.nodes[tag_key]["id"])
            })

            # increase symbol size of page and tag node
            self.nodes[page_key]["symbolSize"] += 1
            self.nodes[tag_key]["symbolSize"] += 1

    def create_graph_json(self, config: MkDocsConfig):
        for key, node in self.nodes.items():
            self.data["nodes"].append({
                "id": str(node["id"]),
                "name": node["title"],
                "symbolSize": node["symbolSize"],
                "value": node["url"]
            })

        filename = os.path.join(config['site_dir'], 'assets', 'javascripts', 'graph.json')
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2)

    # MkDocs plugin hooks
    def on_nav(self, nav: MkDocsNav, files: MkDocsFiles, config: MkDocsConfig, **kwargs):
        self.collect_pages(nav, config)

    def on_page_markdown(self, markdown: str, page: MkDocsPage, config: MkDocsConfig, files: MkDocsFiles, **kwargs):
        self.parse_markdown(markdown, page)

    def on_env(self, env, config: MkDocsConfig, files: MkDocsFiles):
        self.create_graph_json(config)
