import json
import time
import os
import collections
import itertools
import hashlib
import ast
import operator as op
import urlparse

import flask
import redis
import pygeoip

from flask import *
from flask.ext.bootstrap import Bootstrap

from datetime import timedelta, datetime
from functools import update_wrapper

app = Flask(__name__)
Bootstrap(app)

redis_urls = ['REDISTOGO_URL', 'REDISCLOUD_URL', 'REDIS_URL']
for redis_url in redis_urls:
	if redis_url in os.environ:
		r = redis.utils.from_url(os.environ[redis_url])
		break
else:
	r = redis.Redis()

gi = pygeoip.GeoIP('GeoLiteCity.dat', pygeoip.MEMORY_CACHE)

namespace = os.environ.get('COUNTR_NAMESPACE', 'ns')
auth_password = os.environ.get('COUNTR_PASSWORD', None)

dimension_values_key_structure = '{namespace}:dimension_values:{dimension_k}:{period}:{current_period}:{metric}'
count_key_structure = '{namespace}:count:{dimension_k}:{dimension_v}:{period}:{current_period}:{metric}'
encrypted_key_structure = '{namespace}:encrypted:{encryption_hash}'
periods = {
	'10s': {'period': 10, 'lifetime': 60, 'name': '10 Seconds'},
	'1m': {'period': 60, 'lifetime': 60, 'name': '1 Minute'},
	'10m': {'period': 60 * 10, 'lifetime': 60, 'name': '10 Minutes'},
	'1h': {'period': 60 * 60, 'lifetime': 24, 'name': '1 Hour'},
	'1d': {'period': 60 * 60 * 24, 'lifetime': 30, 'name': '1 Day'},
	'1w': {'period': 60 * 60 * 24 * 7, 'lifetime': 52, 'name': '1 Week'},
	'1mo': {'period': 60 * 60 * 24 * 30, 'lifetime': 12, 'name': '1 Month'},
	'1y': {'period': 60 * 60 * 24 * 7, 'lifetime':10, 'name': '1 Year'},
	'f': {'period': 10, 'lifetime' : 0, 'name': 'Forever'},
}

operators = {ast.Add: op.add, ast.Sub: op.sub, ast.Mult: op.mul,
             ast.Div: op.truediv, ast.Mod: op.mod}

def crossdomain(origin=None, methods=None, headers=None,
                max_age=21600, attach_to_all=True,
                automatic_options=True):
    if methods is not None:
        methods = ', '.join(sorted(x.upper() for x in methods))
    if headers is not None and not isinstance(headers, basestring):
        headers = ', '.join(x.upper() for x in headers)
    if not isinstance(origin, basestring):
        origin = ', '.join(origin)
    if isinstance(max_age, timedelta):
        max_age = max_age.total_seconds()

    def get_methods():
        if methods is not None:
            return methods

        options_resp = current_app.make_default_options_response()
        return options_resp.headers['allow']

    def decorator(f):
        def wrapped_function(*args, **kwargs):
            if automatic_options and request.method == 'OPTIONS':
                resp = current_app.make_default_options_response()
            else:
                resp = make_response(f(*args, **kwargs))
            if not attach_to_all and request.method != 'OPTIONS':
                return resp

            h = resp.headers

            h['Access-Control-Allow-Origin'] = origin
            h['Access-Control-Allow-Methods'] = get_methods()
            h['Access-Control-Max-Age'] = str(max_age)
            if headers is not None:
                h['Access-Control-Allow-Headers'] = headers
            return resp

        f.provide_automatic_options = False
        return update_wrapper(wrapped_function, f)
    return decorator

def auth(request):
	if not request.authorization or (request.authorization and request.authorization.password == auth_password):
		return True
	else:
		return False

def eval_expr(expr):
    return eval_(ast.parse(expr).body[0].value)

def eval_(node):
    if isinstance(node, ast.Num): # <number>
        return node.n
    elif isinstance(node, ast.operator): # <operator>
        return operators[type(node)]
    elif isinstance(node, ast.BinOp): # <left> <operator> <right>
        return eval_(node.op)(eval_(node.left), eval_(node.right))
    else:
        raise TypeError(node)

def iterate_metrics(metrics):
	if 'hits' not in metrics:
		yield ('hits', '1')
	for k, v in metrics.items():
		yield (str(k), str(int(v)))

def iterate_dimensions(dimensions):
	if isinstance(dimensions, basestring):
		dimensions = {dimensions: 'default'}
	if isinstance(dimensions, int):
		dimensions = {str(dimensions): 'default'}
	for k, v in dimensions.items():
		yield (k, v)


def store_data(dimensions, metrics, geoip=False):
	pipe = r.pipeline()
	dimensions = dict(iterate_dimensions(dimensions))
	if geoip:
		geoip_result = gi.record_by_addr(geoip)
		if geoip_result:
			for k in ['city', 'country_name', 'region_name']:
				if k in geoip_result and geoip_result[k]:
					dimensions[k.rstrip('_name')] = geoip_result[k]
		dimensions['remote_ip'] = geoip
	for metric_k, metric_v in iterate_metrics(metrics):
		for dimension_k, dimension_v in dimensions.items():
			for period in periods:
				if period == 'f':
					current_period = 1
				else:
					current_period = int(time.time()) / periods[period]['period']
				count_key = count_key_structure.format(
					namespace=namespace,
					dimension_k=dimension_k,
					dimension_v=dimension_v,
					metric=metric_k,
					period=period,
					current_period=current_period)

				total_count_key = count_key_structure.format(
					namespace=namespace,
					dimension_k=dimension_k,
					dimension_v='*',
					metric=metric_k,
					period=period,
					current_period=current_period)
				
				dimension_values_key = dimension_values_key_structure.format(
					namespace=namespace,
					dimension_k=dimension_k,
					metric=metric_k,
					period=period,
					current_period=current_period)

				pipe.incr(count_key, metric_v)
				pipe.incr(total_count_key, metric_v)
				pipe.sadd(dimension_values_key, count_key)
				if periods[period]['period'] > 0:
					key_lifetime = periods[period]['period'] * (periods[period]['lifetime'] + 1)
					pipe.expire(count_key, key_lifetime)
					pipe.expire(total_count_key, key_lifetime)
					pipe.expire(dimension_values_key, key_lifetime)
	pipe.rpush('{namespace}:spy'.format(namespace=namespace), json.dumps([dimensions, metrics, int(time.time())]))
	pipe.ltrim('{namespace}:spy'.format(namespace=namespace), 0, 1000)
	pipe.execute()

def get_period(request):
	if 'period' in request.args:
		period = request.args.get('period').lower()
		if period not in periods:
			return '1m'
		return period
	else:
		return '1m'

def get_metrics(request):
	if 'metrics' in request.args:
		return request.args.get('metrics').split(',')
	else:
		return ['hits']

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def get_geoip(request):
	if 'X-Forwarded-For' in request.headers:
		return request.headers['X-Forwarded-For'].split(', ')[-1]
	else:
		return request.remote_addr
#Views
@app.route('/record')
@app.route('/pixel')
def record():
	if 'encryption_hash' in request.args:
		dimensions, metrics, geoip = json.loads(r.get(encrypted_key_structure.format(
			namespace=namespace,
			encryption_hash=request.args.get('encryption_hash')
		)))
		if geoip:
			geoip = get_geoip(request)
		store_data(dimensions, metrics, geoip)
		if 'redirect_url' in dimensions:
			return redirect(dimensions[redirect_url])
		if '/pixel' in request.url:
			return send_file('static/pixel.gif')
		return 'ok'
	elif auth(request):
		if 'metrics' in request.args:
			metrics = json.loads(request.args.get('metrics'))
		else:
			metrics = {}
		if 'dimensions' in request.args:
			try:
				dimensions = json.loads(request.args.get('dimensions'))
			except:
				dimensions = request.args.get('dimensions')
		else:
			dimensions = 'default'
		if request.args.get('geoip', '') == 'true':
			geoip = get_geoip(request)
		else:
			geoip = False
		store_data(dimensions, metrics, geoip)
		if request.args.get('encrypt') == 'true':
			serialized = json.dumps([dimensions, metrics, geoip])
			encryption_hash = hashlib.sha256(serialized).hexdigest()
			redis_key = encrypted_key_structure.format(namespace=namespace, encryption_hash=encryption_hash)
			r.set(redis_key, serialized)
			return request.url_root+'record?encryption_hash='+encryption_hash
		if 'redirect_url' in dimensions:
			return redirect(dimensions[redirect_url])
		if '/pixel' in request.url:
			return send_file('static/pixel.gif')

		return 'ok'
	elif auth_password:
		return authenticate()

@app.route('/spy')
def spy():
	if auth(request):
		records = [json.loads(record) for record in r.lrange('{namespace}:spy'.format(namespace=namespace), 0, 1000)]
		records.reverse()
		records = [(dimensions, metrics, datetime.fromtimestamp(insert_time)) for dimensions, metrics, insert_time in records]
		print records
		return render_template('spy.html', records=records)
	else:
		return authenticate()

@app.route('/data.json')
@crossdomain(origin='*')
def data():
	period = get_period(request)
	metrics = get_metrics(request)
	if period == 'f':
		current_period = 1
	else:
		current_period = int(time.time()) / periods[period]['period']
	redis_keys = []
	metrics_data = {}
	dimension = request.args.get('dimension', 'default')
	if '/' in dimension:
		dimension_k, dimension_v = dimension.split('/')
	else:
		dimension_k = dimension
		dimension_v = '*'

	if dimension_v == 'top':
		for metric in metrics:
                        for past_period in range(current_period, current_period-periods[period]['lifetime'], -1):
                                dimension_values_key = dimension_values_key_structure.format(
                                                        namespace=namespace,
                                                        dimension_k=dimension_k,
                                                        metric=metric,
                                                        period=period,
                                                        current_period=past_period)

                                dimension_values_keys = r.smembers(dimension_values_key)
                                if len(dimension_values_keys):
                                        dimension_values_scores = [int(v) if v != None else 0 for v in r.mget(dimension_values_keys)]
                                        for key, score in sorted(zip(dimension_values_keys, dimension_values_scores), key=lambda x: x[1], reverse=True)[:10]:
                                                d_v = key.split(':')[3]
                                                if metric != 'hits':
                                                        metric_name = d_v+' - '+metric
                                                else:
                                                        metric_name = d_v
                                                if metric_name not in metrics_data:
                                                        metrics_data[metric_name] = {}
                                                metrics_data[metric_name][past_period] = score
                        for past_period in range(current_period, current_period-periods[period]['lifetime'], -1):
                                for metric in metrics_data:
                                        if past_period not in metrics_data[metric]:
                                                metrics_data[metric][past_period] = 0

	else:
		for metric in metrics:
			if metric != 'total' and ':' not in metric:
				metrics_data[metric] = {current_period: 0}
				for past_period in range(current_period, current_period-periods[period]['lifetime'], -1):	
					redis_keys.append((count_key_structure.format(
						namespace=namespace,
						dimension_k=dimension_k,
						dimension_v=dimension_v,
						metric=metric,
						period=period,
						current_period=past_period), metric, past_period))

		redis_results = [int(v) if v != None else 0 for v in r.mget((r_k[0] for r_k in redis_keys))]
		for k, v in zip(redis_keys, redis_results):
			metrics_data[k[1]][k[2]] = v

	if 'total' in metrics:
		total_dict = collections.defaultdict(int)
		for metric_k, metric_v in metrics_data.items():
			if metric_k != 'hits':
				for k, v in metric_v.items():
					total_dict[k] += v
		metrics_data['total'] = total_dict

	for metric in metrics:
		if ':' in metric:
			metric_name, expression = metric.split(':')
			metrics_data[metric_name] = {}
			for past_period in range(current_period, current_period-periods[period]['lifetime'], -1):
				compiled_expression = expression.format(**{k: metrics_data[k][past_period] for k in metrics_data.keys() if 
					':' not in k and past_period in metrics_data[k]})
				try:
					metrics_data[metric_name][past_period] = eval_expr(compiled_expression)
				except:
					metrics_data[metric_name][past_period] = 0

	metrics_data['_reload_interval'] = min(30, periods[period]['period'])
	if periods[period]['period'] < 60:
		metrics_data['_date_format'] = 'HH:mm:ss'
	elif periods[period]['period'] < 60 * 60 * 24:
		metrics_data['_date_format'] = 'HH:mm'
	else:
		metrics_data['_date_format'] = 'YYYY/MM/DD'
	metrics_data['_period_length'] = periods[period]['period']
	metrics_data['_period_name'] = periods[period]['name']

	return jsonify(**metrics_data)

@app.route('/encrypted')
def encrypted():
	if auth(request):
		keys = r.keys('{namespace}:encrypted:*'.format(namespace=namespace))
		if len(keys):
			records = [{'encryption_hash': key.split(':')[-1], 'dimensions': json.loads(data)[0], 'metrics': json.loads(data)[1]} for key, data in zip(keys, r.mget(keys))]
		else:
			records = None
		return render_template('encrypted.html', records=records)
	else:
		return authenticate()

@app.route('/graph.html')
def html_graph():
	if auth(request):
		period = get_period(request)
		if 'metrics' in request.args:
			metrics = request.args.get('metrics').replace('+', '%2B')
		else:
			metrics = 'hits'
		dimension = request.args.get('dimension', 'default')
		title = request.args.get('title', 'Untitled Countr Graph')
		return render_template('graph.html', period=period, metrics=metrics, title=title, dimension=dimension)
	else:
		return authenticate()

if __name__ == '__main__':
	port = int(os.environ.get('PORT', 5000))
	app.run(host='0.0.0.0', port=port, debug=True)
