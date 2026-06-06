// =============================================================================
// VENDORED THIRD-PARTY CODE — d3-sankey (layout math only)
// -----------------------------------------------------------------------------
// Source:  d3-sankey  https://github.com/d3/d3-sankey
// Version: 0.12.3 (the sankey layout) + the handful of d3-array reducers it uses
//          (min/max/sum/least, inlined) — extracted from d3-array 3.x.
// License: ISC (d3-sankey) / ISC (d3-array). Copyright Mike Bostock.
//
//   Permission to use, copy, modify, and/or distribute this software for any
//   purpose with or without fee is hereby granted, provided that the above
//   copyright notice and this permission notice appear in all copies.
//
//   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
//   SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
//   OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
//   CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
// NOTE (architecture.md §3.4 deviation): this is the project's first frontend
// dependency, an explicit accepted exception for the live flow-trace view. Only
// the LAYOUT is vendored — d3-selection/d3-shape/d3-drag are NOT included; the
// caller renders the SVG itself and draws link paths with a hand-rolled cubic
// Bézier. Loaded with a relative <script src> so the app stays fully offline
// (no CDN, no network). The vendored region is everything in this file.
// =============================================================================
(function (global) {
  'use strict';

  // ---- d3-array reducers (inlined subset) ----------------------------------
  function min(values, valueof) {
    let m;
    if (valueof === undefined) {
      for (const v of values) if (v != null && (m > v || (m === undefined && v >= v))) m = v;
    } else {
      let i = -1;
      for (let v of values) if ((v = valueof(v, ++i, values)) != null && (m > v || (m === undefined && v >= v))) m = v;
    }
    return m;
  }
  function max(values, valueof) {
    let m;
    if (valueof === undefined) {
      for (const v of values) if (v != null && (m < v || (m === undefined && v >= v))) m = v;
    } else {
      let i = -1;
      for (let v of values) if ((v = valueof(v, ++i, values)) != null && (m < v || (m === undefined && v >= v))) m = v;
    }
    return m;
  }
  function sum(values, valueof) {
    let s = 0;
    if (valueof === undefined) {
      for (let v of values) if ((v = +v)) s += v;
    } else {
      let i = -1;
      for (let v of values) if ((v = +valueof(v, ++i, values))) s += v;
    }
    return s;
  }
  function ascending(a, b) {
    return a == null || b == null ? NaN : a < b ? -1 : a > b ? 1 : a >= b ? 0 : NaN;
  }
  function least(values, compare) {
    compare = compare === undefined ? ascending : compare;
    let min, defined = false;
    for (const value of values) {
      if (defined ? compare(value, min) < 0 : compare(value, value) === 0) {
        min = value;
        defined = true;
      }
    }
    return min;
  }

  // ---- d3-sankey/align.js --------------------------------------------------
  function targetDepth(d) { return d.target.depth; }
  function left(node) { return node.depth; }
  function right(node, n) { return n - 1 - node.height; }
  function justify(node, n) { return node.sourceLinks.length ? node.depth : n - 1; }
  function center(node) {
    return node.targetLinks.length ? node.depth
      : node.sourceLinks.length ? min(node.sourceLinks, targetDepth) - 1
      : 0;
  }

  // ---- d3-sankey/constant.js ----------------------------------------------
  function constant(x) { return function () { return x; }; }

  // ---- d3-sankey/sankey.js -------------------------------------------------
  function ascendingSourceBreadth(a, b) {
    return ascendingBreadth(a.source, b.source) || a.index - b.index;
  }
  function ascendingTargetBreadth(a, b) {
    return ascendingBreadth(a.target, b.target) || a.index - b.index;
  }
  function ascendingBreadth(a, b) {
    return a.y0 - b.y0;
  }
  function value(d) { return d.value; }
  function defaultId(d) { return d.index; }
  function defaultNodes(graph) { return graph.nodes; }
  function defaultLinks(graph) { return graph.links; }
  function find(nodeById, id) {
    const node = nodeById.get(id);
    if (!node) throw new Error('missing: ' + id);
    return node;
  }
  function computeLinkBreadths({ nodes }) {
    for (const node of nodes) {
      let y0 = node.y0;
      let y1 = y0;
      for (const link of node.sourceLinks) {
        link.y0 = y0 + link.width / 2;
        y0 += link.width;
      }
      for (const link of node.targetLinks) {
        link.y1 = y1 + link.width / 2;
        y1 += link.width;
      }
    }
  }

  function Sankey() {
    let x0 = 0, y0 = 0, x1 = 1, y1 = 1; // extent
    let dx = 24; // nodeWidth
    let dy = 8, py; // nodePadding
    let nodes = defaultNodes;
    let links = defaultLinks;
    let nodeId = defaultId;
    let nodeAlign = justify;
    let nodeSort;
    let linkSort;
    let iterations = 6;

    function sankey() {
      const graph = { nodes: nodes.apply(null, arguments), links: links.apply(null, arguments) };
      computeNodeLinks(graph);
      computeNodeValues(graph);
      computeNodeDepths(graph);
      computeNodeHeights(graph);
      computeNodeBreadths(graph);
      computeLinkBreadths(graph);
      return graph;
    }

    sankey.update = function (graph) {
      computeLinkBreadths(graph);
      return graph;
    };

    sankey.nodeId = function (_) { return arguments.length ? (nodeId = typeof _ === 'function' ? _ : constant(_), sankey) : nodeId; };
    sankey.nodeAlign = function (_) { return arguments.length ? (nodeAlign = typeof _ === 'function' ? _ : constant(_), sankey) : nodeAlign; };
    sankey.nodeSort = function (_) { return arguments.length ? (nodeSort = _, sankey) : nodeSort; };
    sankey.nodeWidth = function (_) { return arguments.length ? (dx = +_, sankey) : dx; };
    sankey.nodePadding = function (_) { return arguments.length ? (dy = py = +_, sankey) : dy; };
    sankey.nodes = function (_) { return arguments.length ? (nodes = typeof _ === 'function' ? _ : constant(_), sankey) : nodes; };
    sankey.links = function (_) { return arguments.length ? (links = typeof _ === 'function' ? _ : constant(_), sankey) : links; };
    sankey.linkSort = function (_) { return arguments.length ? (linkSort = _, sankey) : linkSort; };
    sankey.size = function (_) { return arguments.length ? (x0 = y0 = 0, x1 = +_[0], y1 = +_[1], sankey) : [x1 - x0, y1 - y0]; };
    sankey.extent = function (_) { return arguments.length ? (x0 = +_[0][0], x1 = +_[1][0], y0 = +_[0][1], y1 = +_[1][1], sankey) : [[x0, y0], [x1, y1]]; };
    sankey.iterations = function (_) { return arguments.length ? (iterations = +_, sankey) : iterations; };

    function computeNodeLinks({ nodes, links }) {
      for (const [i, node] of nodes.entries()) {
        node.index = i;
        node.sourceLinks = [];
        node.targetLinks = [];
      }
      const nodeById = new Map(nodes.map((d, i) => [nodeId(d, i, nodes), d]));
      for (const [i, link] of links.entries()) {
        link.index = i;
        let { source, target } = link;
        if (typeof source !== 'object') source = link.source = find(nodeById, source);
        if (typeof target !== 'object') target = link.target = find(nodeById, target);
        source.sourceLinks.push(link);
        target.targetLinks.push(link);
      }
      if (linkSort != null) {
        for (const { sourceLinks, targetLinks } of nodes) {
          sourceLinks.sort(linkSort);
          targetLinks.sort(linkSort);
        }
      }
    }

    function computeNodeValues({ nodes }) {
      for (const node of nodes) {
        node.value = node.fixedValue === undefined
          ? Math.max(sum(node.sourceLinks, value), sum(node.targetLinks, value))
          : node.fixedValue;
      }
    }

    function computeNodeDepths({ nodes }) {
      const n = nodes.length;
      let current = new Set(nodes);
      let next = new Set();
      let x = 0;
      while (current.size) {
        for (const node of current) {
          node.depth = x;
          for (const { target } of node.sourceLinks) next.add(target);
        }
        if (++x > n) throw new Error('circular link');
        current = next;
        next = new Set();
      }
    }

    function computeNodeHeights({ nodes }) {
      const n = nodes.length;
      let current = new Set(nodes);
      let next = new Set();
      let x = 0;
      while (current.size) {
        for (const node of current) {
          node.height = x;
          for (const { source } of node.targetLinks) next.add(source);
        }
        if (++x > n) throw new Error('circular link');
        current = next;
        next = new Set();
      }
    }

    function computeNodeLayers({ nodes }) {
      const x = max(nodes, (d) => d.depth) + 1;
      const kx = (x1 - x0 - dx) / (x - 1);
      const columns = new Array(x);
      for (const node of nodes) {
        const i = Math.max(0, Math.min(x - 1, Math.floor(nodeAlign.call(null, node, x))));
        node.layer = i;
        node.x0 = x0 + i * kx;
        node.x1 = node.x0 + dx;
        if (columns[i]) columns[i].push(node);
        else columns[i] = [node];
      }
      if (nodeSort) for (const column of columns) column.sort(nodeSort);
      return columns;
    }

    function initializeNodeBreadths(columns) {
      const ky = min(columns, (c) => (y1 - y0 - (c.length - 1) * py) / sum(c, value));
      for (const nodes of columns) {
        let y = y0;
        for (const node of nodes) {
          node.y0 = y;
          node.y1 = y + node.value * ky;
          y = node.y1 + py;
          for (const link of node.sourceLinks) link.width = link.value * ky;
        }
        y = (y1 - y + py) / (nodes.length + 1);
        for (let i = 0; i < nodes.length; ++i) {
          const node = nodes[i];
          node.y0 += y * (i + 1);
          node.y1 += y * (i + 1);
        }
        reorderLinks(nodes);
      }
    }

    function computeNodeBreadths(graph) {
      const columns = computeNodeLayers(graph);
      py = Math.min(dy, (y1 - y0) / (max(columns, (c) => c.length) - 1));
      initializeNodeBreadths(columns);
      for (let i = 0; i < iterations; ++i) {
        const alpha = Math.pow(0.99, i);
        const beta = Math.max(1 - alpha, (i + 1) / iterations);
        relaxRightToLeft(columns, alpha, beta);
        relaxLeftToRight(columns, alpha, beta);
      }
    }

    function relaxLeftToRight(columns, alpha, beta) {
      for (let i = 1, n = columns.length; i < n; ++i) {
        const column = columns[i];
        for (const target of column) {
          let y = 0, w = 0;
          for (const { source, value } of target.targetLinks) {
            let v = value * (target.layer - source.layer);
            y += targetTop(source, target) * v;
            w += v;
          }
          if (!(w > 0)) continue;
          let dy = (y / w - target.y0) * alpha;
          target.y0 += dy;
          target.y1 += dy;
          reorderNodeLinks(target);
        }
        if (nodeSort === undefined) column.sort(ascendingBreadth);
        resolveCollisions(column, beta);
      }
    }

    function relaxRightToLeft(columns, alpha, beta) {
      for (let n = columns.length, i = n - 2; i >= 0; --i) {
        const column = columns[i];
        for (const source of column) {
          let y = 0, w = 0;
          for (const { target, value } of source.sourceLinks) {
            let v = value * (target.layer - source.layer);
            y += sourceTop(source, target) * v;
            w += v;
          }
          if (!(w > 0)) continue;
          let dy = (y / w - source.y0) * alpha;
          source.y0 += dy;
          source.y1 += dy;
          reorderNodeLinks(source);
        }
        if (nodeSort === undefined) column.sort(ascendingBreadth);
        resolveCollisions(column, beta);
      }
    }

    function resolveCollisions(nodes, alpha) {
      const i = nodes.length >> 1;
      const subject = nodes[i];
      resolveCollisionsBottomToTop(nodes, subject.y0 - py, i - 1, alpha);
      resolveCollisionsTopToBottom(nodes, subject.y1 + py, i + 1, alpha);
      resolveCollisionsBottomToTop(nodes, y1, nodes.length - 1, alpha);
      resolveCollisionsTopToBottom(nodes, y0, 0, alpha);
    }

    function resolveCollisionsTopToBottom(nodes, y, i, alpha) {
      for (; i < nodes.length; ++i) {
        const node = nodes[i];
        const dy = (y - node.y0) * alpha;
        if (dy > 1e-6) node.y0 += dy, node.y1 += dy;
        y = node.y1 + py;
      }
    }

    function resolveCollisionsBottomToTop(nodes, y, i, alpha) {
      for (; i >= 0; --i) {
        const node = nodes[i];
        const dy = (node.y1 - y) * alpha;
        if (dy > 1e-6) node.y0 -= dy, node.y1 -= dy;
        y = node.y0 - py;
      }
    }

    function reorderNodeLinks({ sourceLinks, targetLinks }) {
      if (linkSort === undefined) {
        for (const { source: { sourceLinks } } of targetLinks) sourceLinks.sort(ascendingTargetBreadth);
        for (const { target: { targetLinks } } of sourceLinks) targetLinks.sort(ascendingSourceBreadth);
      }
    }

    function reorderLinks(nodes) {
      if (linkSort === undefined) {
        for (const { sourceLinks, targetLinks } of nodes) {
          sourceLinks.sort(ascendingTargetBreadth);
          targetLinks.sort(ascendingSourceBreadth);
        }
      }
    }

    function targetTop(source, target) {
      let y = source.y0 - (source.sourceLinks.length - 1) * py / 2;
      for (const { target: node, width } of source.sourceLinks) {
        if (node === target) break;
        y += width + py;
      }
      for (const { source: node, width } of target.targetLinks) {
        if (node === source) break;
        y -= width;
      }
      return y;
    }

    function sourceTop(source, target) {
      let y = target.y0 - (target.targetLinks.length - 1) * py / 2;
      for (const { source: node, width } of target.targetLinks) {
        if (node === source) break;
        y += width + py;
      }
      for (const { target: node, width } of source.sourceLinks) {
        if (node === target) break;
        y -= width;
      }
      return y;
    }

    return sankey;
  }

  global.d3Sankey = {
    sankey: Sankey,
    sankeyCenter: center,
    sankeyLeft: left,
    sankeyRight: right,
    sankeyJustify: justify,
  };
})(typeof window !== 'undefined' ? window : this);
