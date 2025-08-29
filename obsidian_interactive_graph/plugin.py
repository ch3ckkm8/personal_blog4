import json
import os
import re

from mkdocs.config.defaults import MkDocsConfig
from mkdocs.plugins import BasePlugin, get_plugin_logger
from mkdocs.structure.files import Files as MkDocsFiles
from mkdocs.structure.pages import Page as MkDocsPage
from mkdocs.structure.nav import Navigation as MkDocsNav


class ObsidianInteractiveGraphPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.logger = get_plugin_logger(__name__)
        self.nodes = {}
        self.site_path = ""
        self.current_id = 0
        self.data = json.loads('{ "nodes": [], "links": [] }')

    @property
    def id(self):
        current_id = self.current_id
        self.current_id += 1
        return current_id

    def get_path(self, base: str, *argv: list[str]) -> str:
        from urllib.parse import urljoin
        result = base
        for path in argv:
            result = urljoin(result, path)
        return result

    def get_page_path(self, page: MkDocsPage) -> str:
        return self.get_path(self.site_path, page.file.src_uri).replace(".md", "")

    def page_if_exists(self, page: str) -> str:
        page = self.get_path(self.site_path, page)
        for k,_ in self.nodes.items():
            if k == page:
                return page
        return None

    def collect_pages(self, nav: MkDocsNav, config: MkDocsConfig):
        for page in nav.pages:
            page.read_source(config=config)
            self.nodes[self.get_page_path(page)] = {
                "id": self.id,
                "title": page.title,
                "url": page.abs_url,
                "symbolSize": 0,
                "markdown": page.markdown,
                "is_index": page.is_index
            }

    def parse_markdown(self, markdown: str, page: MkDocsPage):
        # --- Patterns ---
        WIKI_PATTERN = re.compile(r"(?<!\!)\[\[(?P<wikilink>[^\|^\]^\#]{1,})(?:.*?)\]\]")
        TAG_PATTERN = re.compile(r"#(\w+)")

        page_path = self.get_page_path(page)

        # --- Handle wiki-links ([[link]]) ---
        for match in re.finditer(WIKI_PATTERN, markdown):
            wikilink = match.group('wikilink').strip()

            target_page_path = ""

            if wikilink == "index" and self.nodes[page_path]["is_index"]:
                target_page_path = page_path
            else:
                wikilink = self.page_if_exists(wikilink) or self.page_if_exists(self.get_path(page_path, wikilink)) or wikilink

                abslen = None
                for k,_ in self.nodes.items():
                    for _ in re.finditer(re.compile(r"(.*" + re.escape(wikilink) + r")"), k):
                        curlen = k.count('/')
                        if abslen is None or curlen < abslen:
                            target_page_path = k
                            abslen = curlen

            if target_page_path == "":
                # treat as tag node if no page exists
                if wikilink not in self.nodes:
                    self.nodes[wikilink] = {
                        "id": self.id,
                        "title": wikilink,
                        "url": "",
                        "symbolSize": 1,
                        "markdown": "",
                        "is_index": False
                    }
                target_page_path = wikilink

            link = {
                "source": str(self.nodes[page_path]["id"]),
                "target": str(self.nodes[target_page_path]["id"])
            }
            self.data["links"].append(link)

            self.nodes[page_path]["symbolSize"] = self.nodes[page_path].get("symbolSize", 1) + 1
            self.nodes[target_page_path]["symbolSize"] = self.nodes[target_page_path].get("symbolSize", 1) + 1

        # --- Handle hashtags (#tag) ---
        for match in re.finditer(TAG_PATTERN, markdown):
            tag = match.group(1).strip()

            if tag not in self.nodes:
                self.nodes[tag] = {
                    "id": self.id,
                    "title": tag,
                    "url": "",
                    "symbolSize": 1,
                    "markdown": "",
                    "is_index": False
                }

            link = {
                "source": str(self.nodes[page_path]["id"]),
                "target": str(self.nodes[tag]["id"])
            }
            self.data["links"].append(link)

            self.nodes[page_path]["symbolSize"] = self.nodes[page_path].get("symbolSize", 1) + 1
            self.nodes[tag]["symbolSize"] = self.nodes[tag].get("symbolSize", 1) + 1

    def create_graph_json(self, config: MkDocsConfig):
        for i, (k,v) in enumerate(self.nodes.items()):
            node = {
                "id": str(v["id"]),
                "name": v["title"],
                "symbolSize": v["symbolSize"],
                "value": v["url"]
            }
            self.data["nodes"].append(node)

        filename = os.path.join(config['site_dir'], 'assets', 'javascripts', 'graph.json')
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w') as file:
            json.dump(self.data, file, sort_keys=False, indent=2)

    def on_config(self, config: MkDocsConfig, **kwargs):
        self.site_path = config.site_name + "/"

    def on_nav(self, nav: MkDocsNav, files: MkDocsFiles, config: MkDocsConfig, **kwargs):
        self.collect_pages(nav, config)

    def on_page_markdown(self, markdown: str, page: MkDocsPage, config: MkDocsConfig, files: MkDocsFiles, **kwargs):
        self.parse_markdown(markdown, page)

    def on_env(self, env, config: MkDocsConfig, files: MkDocsFiles):
        self.create_graph_json(config)
