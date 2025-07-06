document.addEventListener('DOMContentLoaded', () => {
  fetch('/api/iocs')
    .then(response => response.json())
    .then(data => {
      const tableBody = document.querySelector('#iocs-table tbody');
      tableBody.innerHTML = ''; // limpiar tabla

      data.forEach(ioc => {
        const row = document.createElement('tr');
        row.innerHTML = `
          <td>${ioc.type}</td>
          <td>${ioc.indicator}</td>
          <td>${ioc.description || ''}</td>
          <td>${ioc.source}</td>
          <td>${ioc.pulse_name || ''}</td>
          <td>${ioc.category || ''}</td>
          <td>${ioc.tags ? ioc.tags.join(', ') : ''}</td>
          <td>${ioc.related_actors ? ioc.related_actors.join(', ') : ''}</td>
          <td>${ioc.ttp ? ioc.ttp.join(', ') : ''}</td>
          <td>${ioc.threat_score}</td>
          <td>${ioc.ingest_time}</td>
          <td>${ioc.first_seen || ''}</td>
          <td>${ioc.last_seen || ''}</td>
        `;
        tableBody.appendChild(row);
      });
    })
    .catch(err => {
      console.error('Error cargando IoCs:', err);
    });
});
console.log('dashboard.js cargado correctamente');
