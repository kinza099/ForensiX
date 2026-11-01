/**
 * ForensiX Interactive Forensic Timeline Controller
 */

const ForensiXTimeline = {
  events: [],
  currentCategory: 'All',
  searchQuery: '',

  categoryColors: {
    'File System': '#3b82f6',
    'Authentication': '#f59e0b',
    'Browser': '#10b981',
    'Network': '#a855f7',
    'System': '#ec4899',
    'Investigation': '#38bdf8'
  },

  setEvents(events) {
    this.events = events || [];
    this.render();
  },

  filterCategory(cat) {
    this.currentCategory = cat;
    this.render();
  },

  filterSearch(query) {
    this.searchQuery = (query || '').toLowerCase().trim();
    this.render();
  },

  getFilteredEvents() {
    return this.events.filter(e => {
      const matchCat = (this.currentCategory === 'All' || e.category === this.currentCategory);
      const matchSearch = !this.searchQuery || 
        (e.title && e.title.toLowerCase().includes(this.searchQuery)) ||
        (e.description && e.description.toLowerCase().includes(this.searchQuery)) ||
        (e.event_type && e.event_type.toLowerCase().includes(this.searchQuery)) ||
        (e.source_ref && e.source_ref.toLowerCase().includes(this.searchQuery));
      return matchCat && matchSearch;
    });
  },

  render() {
    const container = document.getElementById('timeline-stream-container');
    if (!container) return;

    const filtered = this.getFilteredEvents();

    if (filtered.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-title">No Timeline Events Match Criteria</div>
          <div class="empty-state-desc">Try changing category filters or clearing the search query.</div>
        </div>
      `;
      return;
    }

    let html = '';
    let currentDay = '';

    filtered.forEach(e => {
      const day = e.timestamp.slice(0, 10);
      if (day !== currentDay) {
        currentDay = day;
        html += `
          <div style="font-size: 11px; font-weight: 700; color: var(--accent-cyan); text-transform: uppercase; letter-spacing: 1px; margin: 18px 0 10px -10px; display: flex; align-items: center; gap: 8px;">
            <span style="background: var(--bg-card); padding: 3px 8px; border-radius: 4px; border: 1px solid var(--border-color);">
              📅 ${currentDay}
            </span>
            <div style="flex: 1; height: 1px; background: var(--border-color);"></div>
          </div>
        `;
      }

      const color = this.categoryColors[e.category] || '#94a3b8';
      const timeStr = e.timestamp.slice(11, 19);

      html += `
        <div class="timeline-node" onclick="ForensiXApp.showTimelineDetail(${e.id})">
          <div class="timeline-node-marker" style="border-color: ${color}">
            <div style="width: 6px; height: 6px; border-radius: 50%; background: ${color}"></div>
          </div>
          <div class="timeline-node-content">
            <div class="timeline-node-header">
              <span class="timeline-node-title">${e.title}</span>
              <span class="timeline-node-time">${timeStr} UTC</span>
            </div>
            <div class="timeline-node-desc">${e.description || ''}</div>
            <div style="display: flex; gap: 8px; margin-top: 6px; align-items: center;">
              <span class="badge" style="background: ${color}20; color: ${color}; border: 1px solid ${color}40;">${e.category}</span>
              <span style="font-size: 10px; color: var(--text-dim);">${e.source_ref || 'System'}</span>
              ${e.evidence_id ? `<button class="btn btn-sm btn-secondary" style="margin-left: auto; padding: 2px 6px; font-size: 10px;" onclick="event.stopPropagation(); ForensiXApp.inspectEvidence(${e.evidence_id})">Inspect Evidence</button>` : ''}
            </div>
          </div>
        </div>
      `;
    });

    container.innerHTML = html;
  }
};
