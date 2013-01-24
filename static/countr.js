function update_graph(graph_data, graph, graph_id) {
  d3.select(graph_id)
    .attr('height', window.innerHeight / d3.selectAll('.countr-graph')[0].length)
    .datum(graph_data)
    .transition().duration(1000)
    .call(graph);
}

function make_graph(metrics, period, dimension, title, graph, graph_id) {
  var colors = ['#7a92a3', '#0b62a4', '#4da74d', '#FACC00', '#FB9900', '#FB6600', '#FB4800', '#CB0A0A', '#F8F933'];
  var data_url = $('script[src$="countr.js"]').attr('src').replace('/static/countr.js', '/data.json');
  d3.json(data_url+'?period=' + period + '&metrics='+metrics+'&dimension='+dimension, function(data) {
    var graph_data = [];
    var i = 0;
    $.each(data, function(metric, metric_data) {
      if (metric[0] != '_') {
        i++;
        metric_hash = {
          values: [],
          key: metric,
          color: colors[i % colors.length],
        }
        $.each(metric_data, function(metric_k, metric_v) {
          metric_hash['values'].push({x: parseInt(metric_k), y: metric_v});
        });
        graph_data.push(metric_hash);
      }
    });
    if (!graph) {
      graph = nv.models.lineChart();
      graph.margin({bottom: 100});
      graph.xAxis.rotateLabels(-45)
      .axisLabel(title+' - '+data['_period_name']+' Period')
      .tickFormat(function (d) { return moment(new Date(d*data['_period_length']*1000)).format(data['_date_format']); });

      nv.utils.windowResize(function() { d3.select(graph_id).call(graph).attr('height', window.innerHeight / d3.selectAll('.countr-graph')[0].length) });
      update_graph(graph_data, graph, graph_id);
      setInterval(function() { make_graph(metrics, period, dimension, title, graph, graph_id); }, data['_reload_interval'] * 1000); 
    }
    else {
     update_graph(graph_data, graph, graph_id);
    }
  });
}

$(document).ready(function() {
  d3.selectAll('.countr-graph').each(function(svg, i) {
    svg = d3.select(this);
    if (!svg.attr('id')) {
      svg.attr('id', 'countr-'+i);
    }
    make_graph(svg.attr('data-metrics'), svg.attr('data-period'), svg.attr('data-dimension'), svg.attr('data-title'), false, '#'+svg.attr('id'));
  });
});