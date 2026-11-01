/**
 * ForensiX Interactive Force-Directed Relationship Graph Engine
 * High-performance, zero-dependency HTML5 Canvas Network Visualization
 */

class ForensiXGraph {
  constructor(canvasId, inspectorId) {
    this.canvas = document.getElementById(canvasId);
    this.inspector = document.getElementById(inspectorId);
    if (!this.canvas) return;

    this.ctx = this.canvas.getContext('2d');
    this.nodes = [];
    this.edges = [];
    this.nodeMap = new Map();

    // Camera transform
    this.transform = { x: 0, y: 0, scale: 1 };
    this.isDragging = false;
    this.draggedNode = null;
    this.dragStart = { x: 0, y: 0 };
    this.selectedNode = null;

    // Simulation params
    this.alpha = 1.0;
    this.isSimulating = true;

    this.typeColors = {
      case: '#f59e0b',
      evidence: '#6366f1',
      hash: '#a855f7',
      ip_address: '#f43f5e',
      domain: '#10b981',
      url: '#10b981',
      username: '#06b6d4',
      finding: '#f43f5e',
      filename: '#94a3b8'
    };

    this.initEvents();
    this.resize();
  }

  resize() {
    if (!this.canvas) return;
    const rect = this.canvas.parentElement.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    this.width = rect.width;
    this.height = rect.height;
    this.canvas.width = rect.width * dpr;
    this.canvas.height = rect.height * dpr;
    this.ctx.scale(dpr, dpr);
    this.transform.x = this.width / 2;
    this.transform.y = this.height / 2;
  }

  setData(data) {
    this.nodes = (data.nodes || []).map((n, i) => {
      const angle = (i / data.nodes.length) * 2 * Math.PI;
      const radius = 120 + Math.random() * 150;
      return {
        ...n,
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius,
        vx: 0,
        vy: 0,
        radius: n.type === 'case' ? 22 : n.type === 'finding' ? 18 : 14
      };
    });

    this.nodeMap.clear();
    this.nodes.forEach(n => this.nodeMap.set(n.id, n));

    this.edges = (data.edges || []).map(e => ({
      ...e,
      sourceNode: this.nodeMap.get(e.source),
      targetNode: this.nodeMap.get(e.target)
    })).filter(e => e.sourceNode && e.targetNode);

    this.alpha = 1.0;
    this.isSimulating = true;
    this.animate();
  }

  initEvents() {
    window.addEventListener('resize', () => this.resize());

    this.canvas.addEventListener('mousedown', (e) => {
      const pos = this.getCanvasPos(e);
      const clicked = this.findNodeAt(pos.x, pos.y);

      if (clicked) {
        this.draggedNode = clicked;
        this.selectedNode = clicked;
        this.inspectNode(clicked);
      } else {
        this.isDragging = true;
        this.dragStart = { x: e.clientX - this.transform.x, y: e.clientY - this.transform.y };
      }
    });

    window.addEventListener('mousemove', (e) => {
      if (this.draggedNode) {
        const pos = this.getCanvasPos(e);
        this.draggedNode.x = pos.x;
        this.draggedNode.y = pos.y;
        this.draggedNode.vx = 0;
        this.draggedNode.vy = 0;
        this.alpha = 0.3; // Wake simulation slightly
      } else if (this.isDragging) {
        this.transform.x = e.clientX - this.dragStart.x;
        this.transform.y = e.clientY - this.dragStart.y;
      }
    });

    window.addEventListener('mouseup', () => {
      this.draggedNode = null;
      this.isDragging = false;
    });

    this.canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
      this.transform.scale = Math.min(Math.max(0.3, this.transform.scale * zoomFactor), 3);
    });
  }

  getCanvasPos(e) {
    const rect = this.canvas.getBoundingClientRect();
    const clientX = e.clientX - rect.left;
    const clientY = e.clientY - rect.top;
    return {
      x: (clientX - this.transform.x) / this.transform.scale,
      y: (clientY - this.transform.y) / this.transform.scale
    };
  }

  findNodeAt(x, y) {
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const n = this.nodes[i];
      const dx = n.x - x;
      const dy = n.y - y;
      if (Math.sqrt(dx * dx + dy * dy) <= n.radius + 6) {
        return n;
      }
    }
    return null;
  }

  stepSimulation() {
    if (this.alpha < 0.005) {
      this.isSimulating = false;
      return;
    }

    // 1. Repulsion between all nodes (Coulomb's Law)
    for (let i = 0; i < this.nodes.length; i++) {
      const n1 = this.nodes[i];
      for (let j = i + 1; j < this.nodes.length; j++) {
        const n2 = this.nodes[j];
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        if (dist < 300) {
          const force = (300 - dist) / dist * 0.8 * this.alpha;
          n1.vx -= dx * force * 0.05;
          n1.vy -= dy * force * 0.05;
          n2.vx += dx * force * 0.05;
          n2.vy += dy * force * 0.05;
        }
      }
    }

    // 2. Spring attraction along edges (Hooke's Law)
    this.edges.forEach(e => {
      const dx = e.targetNode.x - e.sourceNode.x;
      const dy = e.targetNode.y - e.sourceNode.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const targetDist = 90;
      const force = (dist - targetDist) * 0.04 * this.alpha;

      e.sourceNode.vx += (dx / dist) * force;
      e.sourceNode.vy += (dy / dist) * force;
      e.targetNode.vx -= (dx / dist) * force;
      e.targetNode.vy -= (dy / dist) * force;
    });

    // 3. Center gravity pull
    this.nodes.forEach(n => {
      if (n === this.draggedNode) return;
      n.vx -= n.x * 0.008 * this.alpha;
      n.vy -= n.y * 0.008 * this.alpha;

      // Apply damping & update position
      n.vx *= 0.82;
      n.vy *= 0.82;
      n.x += n.vx;
      n.y += n.vy;
    });

    this.alpha *= 0.985;
  }

  animate() {
    this.stepSimulation();
    this.draw();
    requestAnimationFrame(() => this.animate());
  }

  draw() {
    if (!this.ctx) return;
    this.ctx.clearRect(0, 0, this.width, this.height);

    this.ctx.save();
    this.ctx.translate(this.transform.x, this.transform.y);
    this.ctx.scale(this.transform.scale, this.transform.scale);

    // Draw Edges
    this.edges.forEach(e => {
      const isHighlighted = this.selectedNode && (e.sourceNode === this.selectedNode || e.targetNode === this.selectedNode);
      this.ctx.strokeStyle = isHighlighted ? '#38bdf8' : '#23334d';
      this.ctx.lineWidth = isHighlighted ? 2 : 1;

      this.ctx.beginPath();
      this.ctx.moveTo(e.sourceNode.x, e.sourceNode.y);
      this.ctx.lineTo(e.targetNode.x, e.targetNode.y);
      this.ctx.stroke();

      // Draw edge label if selected or zoomed in
      if (this.transform.scale > 0.8 || isHighlighted) {
        const mx = (e.sourceNode.x + e.targetNode.x) / 2;
        const my = (e.sourceNode.y + e.targetNode.y) / 2;
        this.ctx.fillStyle = isHighlighted ? '#93c5fd' : '#475569';
        this.ctx.font = '8px Inter, sans-serif';
        this.ctx.textAlign = 'center';
        this.ctx.fillText(e.label, mx, my - 2);
      }
    });

    // Draw Nodes
    this.nodes.forEach(n => {
      const isSelected = this.selectedNode === n;
      const baseColor = this.typeColors[n.type] || '#94a3b8';

      // Selection ring
      if (isSelected) {
        this.ctx.beginPath();
        this.ctx.arc(n.x, n.y, n.radius + 6, 0, Math.PI * 2);
        this.ctx.fillStyle = 'rgba(56, 189, 248, 0.2)';
        this.ctx.fill();
        this.ctx.strokeStyle = '#38bdf8';
        this.ctx.lineWidth = 2;
        this.ctx.stroke();
      }

      // Main Node Circle
      this.ctx.beginPath();
      this.ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
      this.ctx.fillStyle = baseColor;
      this.ctx.fill();
      this.ctx.strokeStyle = '#0f172a';
      this.ctx.lineWidth = 2;
      this.ctx.stroke();

      // Node Label
      this.ctx.fillStyle = isSelected ? '#f8fafc' : '#cbd5e1';
      this.ctx.font = isSelected ? 'bold 11px Inter, sans-serif' : '10px Inter, sans-serif';
      this.ctx.textAlign = 'center';
      this.ctx.fillText(n.label, n.x, n.y + n.radius + 13);
    });

    this.ctx.restore();
  }

  inspectNode(node) {
    if (!this.inspector) return;
    this.inspector.classList.add('active');

    let html = `
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
        <span class="badge" style="background: ${this.typeColors[node.type]}22; color: ${this.typeColors[node.type]}; border: 1px solid ${this.typeColors[node.type]}44">
          ${node.type.toUpperCase()}
        </span>
        <button class="btn btn-sm btn-secondary" onclick="document.getElementById('graph-inspector').classList.remove('active')">&times;</button>
      </div>
      <h4 style="font-size: 14px; font-weight: 700; color: #f1f5f9; margin-bottom: 8px;">${node.label}</h4>
      <div class="kv-grid" style="margin-top: 12px;">
    `;

    for (const [k, v] of Object.entries(node.details || {})) {
      html += `
        <div class="kv-key">${k}</div>
        <div class="kv-value">${v}</div>
      `;
    }

    // Connected neighbors
    const neighbors = this.edges
      .filter(e => e.sourceNode === node || e.targetNode === node)
      .map(e => e.sourceNode === node ? { node: e.targetNode, rel: e.label } : { node: e.sourceNode, rel: e.label });

    html += `</div>
      <div style="margin-top: 14px; border-top: 1px solid var(--border-color); padding-top: 10px;">
        <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; color: var(--text-dim); margin-bottom: 6px;">
          Connected Entities (${neighbors.length})
        </div>
        <div style="display: flex; flex-direction: column; gap: 4px;">
    `;

    neighbors.forEach(n => {
      html += `
        <div style="font-size: 11.5px; padding: 4px 6px; background: rgba(0,0,0,0.2); border-radius: 4px; display: flex; justify-content: space-between;">
          <span style="color: #38bdf8; cursor: pointer;" onclick="window.graphInstance.selectNodeById('${n.node.id}')">${n.node.label}</span>
          <span style="color: #64748b; font-size: 10px;">${n.rel}</span>
        </div>
      `;
    });

    html += `</div></div>`;
    this.inspector.innerHTML = html;
  }

  selectNodeById(id) {
    const node = this.nodeMap.get(id);
    if (node) {
      this.selectedNode = node;
      this.inspectNode(node);
      // Pan camera towards node
      this.transform.x = this.width / 2 - node.x * this.transform.scale;
      this.transform.y = this.height / 2 - node.y * this.transform.scale;
    }
  }

  resetZoom() {
    this.transform.scale = 1;
    this.transform.x = this.width / 2;
    this.transform.y = this.height / 2;
  }
}
