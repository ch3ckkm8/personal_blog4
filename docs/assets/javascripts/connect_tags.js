document.addEventListener("DOMContentLoaded", function() {
    // Wait a bit to ensure the graph JSON is loaded
    setTimeout(() => {
        if (typeof myChart === "undefined") return;

        // Extract nodes and links
        let graph = myChart.getOption().series[0];
        if (!graph) return;

        let nodes = graph.data;
        let links = graph.links || [];

        // Helper: get tags from a node name
        function getTags(node) {
            // Matches words starting with #
            let match = node.name.match(/#\w+/g);
            return match ? match.map(t => t.toLowerCase()) : [];
        }

        // Build a mapping: node id -> tags
        let nodeTags = {};
        nodes.forEach(node => {
            nodeTags[node.id] = getTags(node);
        });

        // Create edges for nodes that share tags
        for (let i = 0; i < nodes.length; i++) {
            for (let j = i + 1; j < nodes.length; j++) {
                let common = nodeTags[nodes[i].id].filter(tag => nodeTags[nodes[j].id].includes(tag));
                if (common.length > 0) {
                    links.push({ source: nodes[i].id, target: nodes[j].id });
                }
            }
        }

        // Update the graph with new links
        myChart.setOption({
            series: [{
                data: nodes,
                links: links
            }]
        });

    }, 500); // 500ms delay to ensure graph JSON is loaded
});
