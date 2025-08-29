import os
import re
import json

DOCS_DIR = "docs"
OUTPUT_JSON = os.path.join("assets", "javascripts", "graph.json")

nodes = []
links = []

tag_nodes = {}
page_nodes = {}

# Helper: slugify names to use as node ids
def slugify(name):
    return re.sub(r'\W+', '_', name.lower())

# Scan all markdown files
for root, dirs, files in os.walk(DOCS_DIR):
    for file in files:
        if file.endswith(".md"):
            path = os.path.join(root, file)
            with open(path, encoding="utf-8") as f:
                content = f.read()
            
            # Page node
            page_name = os.path.splitext(file)[0]
            page_id = slugify(page_name)
            page_nodes[page_name] = page_id
            nodes.append({
                "id": page_id,
                "name": page_name,
                "symbolSize": 10,
                "value": "/" + os.path.relpath(path, DOCS_DIR).replace("\\","/").replace(".md","/")
            })
            
            # Extract tags (#word)
            tags = re.findall(r"#(\w+)", content)
            for tag in tags:
                tag_id = tag_nodes.get(tag)
                if not tag_id:
                    tag_id = slugify(tag)
                    tag_nodes[tag] = tag_id
                    nodes.append({
                        "id": tag_id,
                        "name": tag,
                        "symbolSize": 5,
                        "value": None
                    })
                # Link page -> tag
                links.append({
                    "source": page_id,
                    "target": tag_id
                })

# Optional: create links between pages sharing the same tag
for tag, tag_id in tag_nodes.items():
    pages_with_tag = [link["source"] for link in links if link["target"] == tag_id]
    for i in range(len(pages_with_tag)):
        for j in range(i+1, len(pages_with_tag)):
            links.append({
                "source": pages_with_tag[i],
                "target": pages_with_tag[j]
            })

# Write JSON
os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
    json.dump({"nodes": nodes, "links": links}, f, indent=2)

print(f"Graph JSON written to {OUTPUT_JSON}")
