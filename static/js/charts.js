/**
 * ForensiX High-Precision Canvas Chart Engine
 * Lightweight, zero-dependency charts for forensic telemetry
 */

const ForensiXCharts = {
  // Royal Indigo + Matte Gunmetal color palette
  colors: [
    '#6366f1', '#10b981', '#06b6d4', '#f43f5e', '#f59e0b',
    '#818cf8', '#ec4899', '#14b8a6', '#a855f7', '#94a3b8'
  ],

  setupCanvas(canvas) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    return { ctx, width: rect.width, height: rect.height };
  },

  drawDonut(canvasId, dataObject) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const { ctx, width, height } = this.setupCanvas(canvas);

    const labels = Object.keys(dataObject);
    const values = Object.values(dataObject);
    const total = values.reduce((a, b) => a + b, 0);

    if (total === 0) {
      ctx.fillStyle = '#556782';
      ctx.font = '11px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('No data available for active case', width / 2, height / 2);
      return;
    }

    const centerX = width * 0.35;
    const centerY = height / 2;
    const outerRadius = Math.min(centerX, centerY) - 14;
    const innerRadius = outerRadius * 0.64;

    let startAngle = -Math.PI / 2;

    values.forEach((val, i) => {
      const sliceAngle = (val / total) * 2 * Math.PI;
      const color = this.colors[i % this.colors.length];

      ctx.beginPath();
      ctx.arc(centerX, centerY, outerRadius, startAngle, startAngle + sliceAngle);
      ctx.arc(centerX, centerY, innerRadius, startAngle + sliceAngle, startAngle, true);
      ctx.closePath();
      ctx.fillStyle = color;
      ctx.fill();

      // Thin separation line
      ctx.strokeStyle = '#0a111c';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      startAngle += sliceAngle;
    });

    // Draw total in center
    ctx.fillStyle = '#f1f5f9';
    ctx.font = 'bold 17px JetBrains Mono, monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(total.toString(), centerX, centerY - 6);
    ctx.fillStyle = '#556782';
    ctx.font = '9px Inter, sans-serif';
    ctx.fillText('ITEMS', centerX, centerY + 11);

    // Draw Legend on the right side
    const legendX = width * 0.68;
    let legendY = 20;
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';

    labels.forEach((lbl, i) => {
      if (legendY > height - 12) return;
      const color = this.colors[i % this.colors.length];
      const count = values[i];
      const pct = Math.round((count / total) * 100);

      // Color dot
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(legendX, legendY, 4, 0, Math.PI * 2);
      ctx.fill();

      // Label & percentage
      ctx.fillStyle = '#8fa0ba';
      ctx.font = '10.5px Inter, sans-serif';
      const labelText = lbl.length > 13 ? lbl.slice(0, 11) + '..' : lbl;
      ctx.fillText(`${labelText} (${pct}%)`, legendX + 10, legendY);

      legendY += 18;
    });
  },

  drawBarChart(canvasId, itemsArray, labelKey = 'slot', valueKey = 'count') {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const { ctx, width, height } = this.setupCanvas(canvas);

    if (!itemsArray || itemsArray.length === 0) {
      ctx.fillStyle = '#556782';
      ctx.font = '11px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('No timeline telemetry recorded for active case', width / 2, height / 2);
      return;
    }

    const maxVal = Math.max(...itemsArray.map(item => item[valueKey]), 1);
    const paddingLeft = 36;
    const paddingBottom = 26;
    const paddingTop = 16;
    const paddingRight = 16;

    const chartWidth = width - paddingLeft - paddingRight;
    const chartHeight = height - paddingTop - paddingBottom;

    // Draw horizontal grid lines
    ctx.strokeStyle = '#162238';
    ctx.lineWidth = 1;
    ctx.fillStyle = '#556782';
    ctx.font = '9px JetBrains Mono, monospace';
    ctx.textAlign = 'right';

    for (let i = 0; i <= 4; i++) {
      const y = paddingTop + (chartHeight / 4) * i;
      const val = Math.round(maxVal - (maxVal / 4) * i);
      ctx.beginPath();
      ctx.moveTo(paddingLeft, y);
      ctx.lineTo(width - paddingRight, y);
      ctx.stroke();
      ctx.fillText(val.toString(), paddingLeft - 6, y + 3);
    }

    // Draw Bars
    const barWidth = Math.max(6, (chartWidth / itemsArray.length) * 0.65);
    const gap = chartWidth / itemsArray.length;

    itemsArray.forEach((item, index) => {
      const val = item[valueKey];
      const barH = (val / maxVal) * chartHeight;
      const x = paddingLeft + gap * index + (gap - barWidth) / 2;
      const y = paddingTop + chartHeight - barH;

      // Gradient
      const grad = ctx.createLinearGradient(0, y, 0, paddingTop + chartHeight);
      grad.addColorStop(0, '#00f0ff');
      grad.addColorStop(1, '#0284c7');

      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.roundRect(x, y, barWidth, barH, [2, 2, 0, 0]);
      ctx.fill();

      // Label
      ctx.fillStyle = '#8fa0ba';
      ctx.font = '8.5px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      let label = item[labelKey] || '';
      if (label.length > 8) {
        label = label.slice(-5);
      }
      ctx.fillText(label, x + barWidth / 2, height - 8);
    });
  }
};
